# SPDX-License-Identifier: Apache-2.0
"""CowFS — public filesystem API with transparent COW."""

from __future__ import annotations

import os
from pathlib import Path

from ._branch import CowBranch


class CowFS:
    """Copy-on-Write filesystem.

    Wraps a directory with COW semantics. All writes go to an isolated
    upper layer. The original directory is never modified until commit.

    Usage::

        with CowFS("/opt/project") as fs:
            fs.write("file.txt", b"hello world")
            data = fs.read("file.txt")
            fs.mkdir("subdir")
            fs.unlink("old.txt")
            entries = fs.listdir(".")
        # Exiting normally commits; exception aborts.

        # Or manually:
        fs = CowFS("/opt/project")
        fs.write("output.txt", b"result")
        fs.commit()  # or fs.abort()
    """

    def __init__(self, workdir: str | Path, storage: str | Path | None = None):
        self._branch = CowBranch(
            Path(workdir),
            Path(storage) if storage else None,
        )
        self._branch.create()

    # --- File I/O ---

    def read(self, path: str) -> bytes:
        """Read a file (checks upper first, then lower)."""
        resolved = self._branch.resolve_read(path)
        return resolved.read_bytes()

    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        """Read a file as text."""
        return self.read(path).decode(encoding)

    def write(self, path: str, data: bytes) -> None:
        """Write data to a file (COW: original untouched)."""
        upper = self._branch.ensure_cow_copy(path)
        upper.write_bytes(data)

    def write_text(self, path: str, text: str, encoding: str = "utf-8") -> None:
        """Write text to a file."""
        self.write(path, text.encode(encoding))

    def open(self, path: str, mode: str = "r"):
        """Open a file with COW semantics.

        Read modes open from upper (if modified) or lower.
        Write modes open from upper (COW copy if needed).
        """
        if "w" in mode or "a" in mode or "x" in mode or "+" in mode:
            real = self._branch.ensure_cow_copy(path)
        else:
            real = self._branch.resolve_read(path)
        return builtins_open(str(real), mode)

    # --- Existence / metadata ---

    def exists(self, path: str) -> bool:
        """Check if a file or directory exists (upper or lower)."""
        from ._branch import _whiteout_path
        if _whiteout_path(self._branch.upper_dir, path).exists():
            return False
        return self._branch.resolve_read(path).exists()

    def stat(self, path: str) -> os.stat_result:
        """Stat a file (checks upper first, then lower)."""
        from ._branch import _whiteout_path
        if _whiteout_path(self._branch.upper_dir, path).exists():
            raise FileNotFoundError(path)
        resolved = self._branch.resolve_read(path)
        return os.stat(str(resolved))

    def isfile(self, path: str) -> bool:
        """Check if path is a file."""
        return self.exists(path) and self._branch.resolve_read(path).is_file()

    def isdir(self, path: str) -> bool:
        """Check if path is a directory."""
        return self.exists(path) and self._branch.resolve_read(path).is_dir()

    # --- Directory operations ---

    def listdir(self, path: str = ".") -> list[str]:
        """List directory entries (merged upper + lower, minus deletions)."""
        from ._handler import CowHandler
        handler = CowHandler(self._branch)
        return handler.list_merged_dir(path)

    def mkdir(self, path: str, exist_ok: bool = False) -> None:
        """Create a directory in the COW upper layer."""
        upper_dir = self._branch.upper_dir / path
        upper_dir.mkdir(parents=True, exist_ok=exist_ok)

    # --- File operations ---

    def unlink(self, path: str) -> None:
        """Delete a file (COW: original untouched, whiteout created)."""
        from ._handler import CowHandler
        handler = CowHandler(self._branch)
        abs_path = str(self._branch.workdir / path)
        if not handler.handle_unlink(abs_path):
            raise FileNotFoundError(path)

    def rmdir(self, path: str) -> None:
        """Remove a directory."""
        from ._handler import CowHandler
        handler = CowHandler(self._branch)
        abs_path = str(self._branch.workdir / path)
        if not handler.handle_unlink(abs_path, is_dir=True):
            raise FileNotFoundError(path)

    def rename(self, src: str, dst: str) -> None:
        """Rename a file or directory (in COW upper layer)."""
        from ._handler import CowHandler
        handler = CowHandler(self._branch)
        abs_src = str(self._branch.workdir / src)
        abs_dst = str(self._branch.workdir / dst)
        handler.handle_rename(abs_src, abs_dst)

    def symlink(self, target: str, link: str) -> None:
        """Create a symbolic link in the COW upper layer."""
        upper_link = self._branch.upper_dir / link
        upper_link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, str(upper_link))

    def link(self, src: str, dst: str) -> None:
        """Create a hard link in the COW upper layer."""
        from ._handler import CowHandler
        handler = CowHandler(self._branch)
        abs_src = str(self._branch.workdir / src)
        abs_dst = str(self._branch.workdir / dst)
        handler.handle_link(abs_src, abs_dst)

    def readlink(self, path: str) -> str:
        """Read a symbolic link target."""
        upper = self._branch.upper_dir / path
        lower = self._branch.workdir / path
        if upper.is_symlink():
            return os.readlink(str(upper))
        if lower.is_symlink():
            return os.readlink(str(lower))
        raise OSError(f"Not a symlink: {path}")

    def chmod(self, path: str, mode: int) -> None:
        """Change file mode (COW copy if needed)."""
        upper = self._branch.ensure_cow_copy(path)
        os.chmod(str(upper), mode)

    def truncate(self, path: str, length: int) -> None:
        """Truncate a file (COW copy if needed)."""
        upper = self._branch.ensure_cow_copy(path)
        os.truncate(str(upper), length)

    # --- Lifecycle ---

    def commit(self) -> None:
        """Merge all COW writes back to the original directory."""
        self._branch.commit()

    def abort(self) -> None:
        """Discard all COW writes. Original directory unchanged."""
        self._branch.abort()

    # --- Context manager ---

    def __enter__(self) -> CowFS:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._branch.finished:
            return
        if exc_type is None:
            self.commit()
        else:
            self.abort()


# Avoid shadowing built-in open
import builtins as _builtins
builtins_open = _builtins.open
