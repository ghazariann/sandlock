# SPDX-License-Identifier: Apache-2.0
"""Seccomp notif-based Copy-on-Write filesystem isolation.

No mount namespace, no FUSE, no dependencies. Uses seccomp user
notification to intercept openat() and redirect writes to a COW
upper directory. The original workdir is never modified.

Flow::

    child calls open("file.txt", O_WRONLY)
        ↓
    seccomp notif intercepts
        ↓
    is path under workdir?
        no  → allow (continue)
        yes → is file in upper?
            yes → open upper copy, inject fd
            no  → copy lower→upper (COW), open upper, inject fd

This handles mmap correctly: the fd the child receives points to the
upper copy, so mmap writes go to the copy, not the original.

Usage::

    branch = CowBranch(workdir=Path("/opt/project"))
    branch.create()

    # Pass to NotifSupervisor — it calls handle_open() for each openat
    handler = CowHandler(branch)

    # After sandbox exits:
    branch.commit()   # merge writes to workdir
    # or
    branch.abort()    # discard all writes
"""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from .exceptions import BranchError
from ._cow_base import CowBranchBase, merge_upper_to_target, cleanup_branch_dir

# O_* flags for detecting writes
O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100
O_TRUNC = 0o1000
O_APPEND = 0o2000

_WRITE_FLAGS = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND


def _whiteout_path(upper_dir: Path, rel_path: str) -> Path:
    """Return the whiteout marker path for a deleted file.

    Whiteout is stored as a sibling: upper/<dirname>/.wh.<basename>
    """
    return upper_dir / os.path.dirname(rel_path) / f".wh.{os.path.basename(rel_path)}"


class CowBranch(CowBranchBase):
    """Seccomp notif-based COW. No namespaces, no dependencies."""

    def __init__(self, workdir: Path, storage: Path | None = None):
        self._workdir = Path(workdir)
        self._storage = storage or Path(f"/tmp/sandlock-cow-{os.getpid()}")
        self._branch_id: str | None = None
        self._finished = False

    @property
    def workdir(self) -> Path:
        return self._workdir

    @property
    def path(self) -> Path:
        """For CowBranch, path is the original workdir (no merged view)."""
        return self._workdir

    @property
    def branch_id(self) -> str | None:
        return self._branch_id

    @property
    def upper_dir(self) -> Path:
        if self._branch_id is None:
            raise BranchError("Branch not created yet")
        return self._storage / self._branch_id / "upper"

    @property
    def finished(self) -> bool:
        return self._finished

    def create(self) -> Path:
        """Create the COW upper directory."""
        self._branch_id = uuid.uuid4().hex[:12]
        branch_dir = self._storage / self._branch_id
        branch_dir.mkdir(parents=True, exist_ok=True)
        (branch_dir / "upper").mkdir(exist_ok=True)
        return self._workdir

    def ensure_cow_copy(self, rel_path: str) -> Path:
        """Ensure a COW copy exists in upper. Returns the upper path.

        If the file exists in lower (workdir) but not in upper, copies it.
        If it exists in neither, returns the upper path (for new files).
        """
        upper_file = self.upper_dir / rel_path
        lower_file = self._workdir / rel_path

        if upper_file.exists():
            return upper_file

        upper_file.parent.mkdir(parents=True, exist_ok=True)

        if lower_file.exists():
            shutil.copy2(str(lower_file), str(upper_file))

        return upper_file

    def resolve_read(self, rel_path: str) -> Path:
        """Resolve a read path: upper if modified, else lower."""
        upper_file = self.upper_dir / rel_path
        if upper_file.exists():
            return upper_file
        return self._workdir / rel_path

    def commit(self) -> None:
        """Merge upper dir writes into workdir."""
        if self._finished:
            return
        if self._branch_id is None:
            raise BranchError("Branch not created yet")

        upper = self.upper_dir
        target = self._workdir

        # Process whiteouts first — delete corresponding target files
        for root, dirs, files in os.walk(upper):
            rel = os.path.relpath(root, upper)
            for f in files:
                if f.startswith(".wh."):
                    original_name = f[4:]
                    dest = target / rel / original_name
                    if dest.is_dir():
                        shutil.rmtree(str(dest), ignore_errors=True)
                    elif dest.exists():
                        dest.unlink()

        # Copy non-whiteout files from upper to target
        for root, dirs, files in os.walk(upper):
            rel = os.path.relpath(root, upper)
            for d in dirs:
                dest = target / rel / d
                dest.mkdir(parents=True, exist_ok=True)
            for f in files:
                if not f.startswith(".wh."):
                    src = Path(root) / f
                    dest = target / rel / f
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(src), str(dest))

        cleanup_branch_dir(self._storage, self._branch_id)
        self._finished = True

    def abort(self) -> None:
        """Discard all writes."""
        if self._finished:
            return
        if self._branch_id is None:
            raise BranchError("Branch not created yet")
        cleanup_branch_dir(self._storage, self._branch_id)
        self._finished = True


class CowHandler:
    """Handles seccomp notif openat() interception for COW.

    Stateless — all state lives in the CowBranch. This class
    provides the decision logic for the notif supervisor.

    Can be extracted into a standalone module in the future.
    """

    def __init__(self, branch: CowBranch):
        self._branch = branch
        self._workdir_str = str(branch.workdir)

    @property
    def workdir(self) -> str:
        return self._workdir_str

    def matches(self, path: str) -> bool:
        """Check if a path is under the COW workdir."""
        return path.startswith(self._workdir_str + "/") or path == self._workdir_str

    def handle_open(self, path: str, flags: int) -> str | None:
        """Determine the real path to open for a COW-intercepted openat.

        Args:
            path: Absolute path the child is trying to open.
            flags: Open flags (O_WRONLY, O_RDWR, O_CREAT, etc.)

        Returns:
            Path to open (in upper or lower dir), or None to let
            the kernel handle it (path not found in either).
        """
        # Don't redirect directory opens — getdents handles dir merging
        O_DIRECTORY = 0o200000
        if flags & O_DIRECTORY:
            return None

        rel_path = os.path.relpath(path, self._workdir_str)
        is_write = bool(flags & _WRITE_FLAGS)

        if is_write:
            try:
                upper_file = self._branch.ensure_cow_copy(rel_path)
                return str(upper_file)
            except OSError:
                return None
        else:
            resolved = self._branch.resolve_read(rel_path)
            if resolved.exists():
                return str(resolved)
            return None

    def handle_unlink(self, path: str, is_dir: bool = False) -> bool:
        """Handle unlink/rmdir: delete from upper, create whiteout.

        Args:
            path: Absolute path to delete.
            is_dir: True for rmdir (AT_REMOVEDIR), False for unlink.

        Returns True if handled (respond 0), False to let kernel handle.
        """
        rel_path = os.path.relpath(path, self._workdir_str)
        upper_file = self._branch.upper_dir / rel_path
        lower_file = Path(self._workdir_str) / rel_path

        # Delete from upper if exists
        if upper_file.exists():
            if is_dir and upper_file.is_dir():
                shutil.rmtree(str(upper_file), ignore_errors=True)
            elif not is_dir:
                upper_file.unlink()

        # If exists in lower, create whiteout marker as sibling:
        # upper/<dirname>/.wh.<basename>
        if lower_file.exists() or lower_file.is_symlink():
            whiteout = _whiteout_path(self._branch.upper_dir, rel_path)
            whiteout.parent.mkdir(parents=True, exist_ok=True)
            whiteout.touch()
            return True

        # File doesn't exist in either — let kernel return ENOENT
        return False

    def handle_mkdir(self, path: str, mode: int) -> bool:
        """Handle mkdirat: create directory in upper.

        Returns True if handled, False to continue.
        """
        rel_path = os.path.relpath(path, self._workdir_str)
        upper_dir = self._branch.upper_dir / rel_path
        upper_dir.mkdir(parents=True, exist_ok=True)
        return True

    def handle_stat(self, path: str) -> str | None:
        """Handle newfstatat/statx: resolve to upper or lower path.

        Returns the real path to stat, or None if deleted/nonexistent.
        """
        rel_path = os.path.relpath(path, self._workdir_str)

        # Check for whiteout (deleted file)
        if _whiteout_path(self._branch.upper_dir, rel_path).exists():
            return None

        resolved = self._branch.resolve_read(rel_path)
        if resolved.exists():
            return str(resolved)
        return None

    def handle_rename(self, old_path: str, new_path: str) -> bool:
        """Handle renameat2: rename in upper dir.

        Returns True if handled, False to continue.
        """
        old_rel = os.path.relpath(old_path, self._workdir_str)
        new_rel = os.path.relpath(new_path, self._workdir_str)

        # Ensure source exists in upper (COW copy if needed)
        old_upper = self._branch.ensure_cow_copy(old_rel)
        new_upper = self._branch.upper_dir / new_rel
        new_upper.parent.mkdir(parents=True, exist_ok=True)
        old_upper.rename(new_upper)
        return True

    def list_merged_dir(self, rel_path: str) -> list[str]:
        """List directory entries merging upper + lower, minus whiteouts."""
        lower_dir = Path(self._workdir_str) / rel_path
        upper_dir = self._branch.upper_dir / rel_path

        entries = set()
        whiteouts = set()

        # Collect whiteouts — stored as .wh.<name> as siblings in upper dir
        scan_dir = self._branch.upper_dir / rel_path if rel_path != "." else self._branch.upper_dir
        if scan_dir.is_dir():
            for e in scan_dir.iterdir():
                if e.name.startswith(".wh."):
                    whiteouts.add(e.name[4:])  # strip ".wh." prefix

        # Upper entries (skip whiteout markers)
        if upper_dir.is_dir():
            for e in upper_dir.iterdir():
                if not e.name.startswith(".wh."):
                    entries.add(e.name)

        # Lower entries (not whited out)
        if lower_dir.is_dir():
            for e in lower_dir.iterdir():
                if e.name not in whiteouts:
                    entries.add(e.name)

        return sorted(entries)

    def handle_symlink(self, target: str, linkpath: str) -> bool:
        """Handle symlink/symlinkat: create symlink in upper."""
        rel_path = os.path.relpath(linkpath, self._workdir_str)
        upper_link = self._branch.upper_dir / rel_path
        upper_link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, str(upper_link))
        return True

    def handle_link(self, oldpath: str, newpath: str) -> bool:
        """Handle link/linkat: create hard link in upper."""
        old_rel = os.path.relpath(oldpath, self._workdir_str)
        new_rel = os.path.relpath(newpath, self._workdir_str)
        # Ensure source is in upper (COW copy)
        old_upper = self._branch.ensure_cow_copy(old_rel)
        new_upper = self._branch.upper_dir / new_rel
        new_upper.parent.mkdir(parents=True, exist_ok=True)
        os.link(str(old_upper), str(new_upper))
        return True

    def handle_chmod(self, path: str, mode: int) -> bool:
        """Handle chmod/fchmodat: chmod in upper (COW copy if needed)."""
        rel_path = os.path.relpath(path, self._workdir_str)
        upper_file = self._branch.ensure_cow_copy(rel_path)
        os.chmod(str(upper_file), mode)
        return True

    def handle_readlink(self, path: str) -> str | None:
        """Handle readlink: resolve symlink from upper or lower.

        Returns the link target, or None if not a symlink.
        """
        rel_path = os.path.relpath(path, self._workdir_str)
        upper_file = self._branch.upper_dir / rel_path
        lower_file = Path(self._workdir_str) / rel_path

        if upper_file.is_symlink():
            return os.readlink(str(upper_file))
        if lower_file.is_symlink():
            return os.readlink(str(lower_file))
        return None

    def handle_truncate(self, path: str, length: int) -> bool:
        """Handle truncate: truncate in upper (COW copy if needed)."""
        rel_path = os.path.relpath(path, self._workdir_str)
        upper_file = self._branch.ensure_cow_copy(rel_path)
        os.truncate(str(upper_file), length)
        return True

    @property
    def upper_dir(self) -> Path:
        return self._branch.upper_dir
