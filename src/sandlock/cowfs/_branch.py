# SPDX-License-Identifier: Apache-2.0
"""CowBranch: manages COW upper directory for seccomp-based isolation."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from ..exceptions import BranchError
from .._cow_base import CowBranchBase, cleanup_branch_dir


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
