# SPDX-License-Identifier: Apache-2.0
"""cowfs — Copy-on-Write filesystem.

Provides a filesystem interface with transparent COW. Writes go to an
isolated upper directory; the original is never modified. On commit,
writes merge back. On abort, writes are discarded.

Two modes of operation:

1. **Standalone** — use CowFS directly as a filesystem API::

    with CowFS("/opt/project") as fs:
        fs.write("file.txt", b"hello")
        data = fs.read("file.txt")
        fs.mkdir("subdir")
        entries = fs.listdir(".")
    # commit on success, abort on error

2. **Sandbox integration** — transparent COW via seccomp notif.
   Handled internally by sandlock when ``workdir`` is set.
"""

from ._cowfs import CowFS

__all__ = ["CowFS"]
