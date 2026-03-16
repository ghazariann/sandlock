# SPDX-License-Identifier: Apache-2.0
"""CowHandler: seccomp notif decision logic for COW interception.

Stateless — all state lives in CowBranch. This class provides the
decision logic that the seccomp notif supervisor calls for each
intercepted filesystem syscall.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from ._branch import CowBranch, _whiteout_path

# O_* flags for detecting writes
O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100
O_TRUNC = 0o1000
O_APPEND = 0o2000
O_DIRECTORY = 0o200000

_WRITE_FLAGS = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND


class CowHandler:
    """Handles seccomp notif syscall interception for COW.

    Each handle_* method returns either a result (for the supervisor
    to respond with) or None (to let the kernel handle it).
    """

    def __init__(self, branch: CowBranch):
        self._branch = branch
        self._workdir_str = str(branch.workdir)

    @property
    def workdir(self) -> str:
        return self._workdir_str

    @property
    def upper_dir(self) -> Path:
        return self._branch.upper_dir

    def matches(self, path: str) -> bool:
        """Check if a path is under the COW workdir."""
        return path.startswith(self._workdir_str + "/") or path == self._workdir_str

    def handle_open(self, path: str, flags: int) -> str | None:
        """Determine the real path to open for a COW-intercepted openat.

        Returns path to open, or None to let the kernel handle it.
        """
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

        Returns True if handled, False to let kernel handle.
        """
        rel_path = os.path.relpath(path, self._workdir_str)
        upper_file = self._branch.upper_dir / rel_path
        lower_file = Path(self._workdir_str) / rel_path

        if upper_file.exists():
            if is_dir and upper_file.is_dir():
                shutil.rmtree(str(upper_file), ignore_errors=True)
            elif not is_dir:
                upper_file.unlink()

        if lower_file.exists() or lower_file.is_symlink():
            whiteout = _whiteout_path(self._branch.upper_dir, rel_path)
            whiteout.parent.mkdir(parents=True, exist_ok=True)
            whiteout.touch()
            return True

        return False

    def handle_mkdir(self, path: str, mode: int) -> bool:
        """Handle mkdirat: create directory in upper."""
        rel_path = os.path.relpath(path, self._workdir_str)
        upper_dir = self._branch.upper_dir / rel_path
        upper_dir.mkdir(parents=True, exist_ok=True)
        return True

    def handle_stat(self, path: str) -> str | None:
        """Handle stat: resolve to upper or lower path.

        Returns the real path to stat, or None if deleted/nonexistent.
        """
        rel_path = os.path.relpath(path, self._workdir_str)

        if _whiteout_path(self._branch.upper_dir, rel_path).exists():
            return None

        resolved = self._branch.resolve_read(rel_path)
        if resolved.exists():
            return str(resolved)
        return None

    def handle_rename(self, old_path: str, new_path: str) -> bool:
        """Handle rename: rename in upper dir."""
        old_rel = os.path.relpath(old_path, self._workdir_str)
        new_rel = os.path.relpath(new_path, self._workdir_str)

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

        scan_dir = self._branch.upper_dir / rel_path if rel_path != "." else self._branch.upper_dir
        if scan_dir.is_dir():
            for e in scan_dir.iterdir():
                if e.name.startswith(".wh."):
                    whiteouts.add(e.name[4:])

        if upper_dir.is_dir():
            for e in upper_dir.iterdir():
                if not e.name.startswith(".wh."):
                    entries.add(e.name)

        if lower_dir.is_dir():
            for e in lower_dir.iterdir():
                if e.name not in whiteouts:
                    entries.add(e.name)

        return sorted(entries)

    def handle_symlink(self, target: str, linkpath: str) -> bool:
        """Handle symlink: create symlink in upper."""
        rel_path = os.path.relpath(linkpath, self._workdir_str)
        upper_link = self._branch.upper_dir / rel_path
        upper_link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, str(upper_link))
        return True

    def handle_link(self, oldpath: str, newpath: str) -> bool:
        """Handle link: create hard link in upper."""
        old_rel = os.path.relpath(oldpath, self._workdir_str)
        new_rel = os.path.relpath(newpath, self._workdir_str)
        old_upper = self._branch.ensure_cow_copy(old_rel)
        new_upper = self._branch.upper_dir / new_rel
        new_upper.parent.mkdir(parents=True, exist_ok=True)
        os.link(str(old_upper), str(new_upper))
        return True

    def handle_chmod(self, path: str, mode: int) -> bool:
        """Handle chmod: chmod in upper (COW copy if needed)."""
        rel_path = os.path.relpath(path, self._workdir_str)
        upper_file = self._branch.ensure_cow_copy(rel_path)
        os.chmod(str(upper_file), mode)
        return True

    def handle_readlink(self, path: str) -> str | None:
        """Handle readlink: resolve symlink from upper or lower."""
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
