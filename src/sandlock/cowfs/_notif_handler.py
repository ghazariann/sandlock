# SPDX-License-Identifier: Apache-2.0
"""COW seccomp notif handlers — syscall-level COW operations.

Handles the seccomp notification side of COW: stat injection,
readlink injection, getdents merging, and openat fd injection.
Called by the supervisor for paths under the COW workdir.
"""

from __future__ import annotations

import errno
import os
import struct
from pathlib import Path

from .._seccomp import _SYSCALL_NR
from .._procfs import write_bytes


def handle_cow_open(notif, path: str, flags: int, cow_handler,
                    respond_continue, respond_addfd) -> None:
    """Handle openat under workdir: redirect to COW upper dir."""
    real_path = cow_handler.handle_open(path, flags)
    if real_path is None:
        respond_continue(notif.id)
        return

    try:
        fd = os.open(real_path, flags, 0o666)
    except OSError:
        respond_continue(notif.id)
        return

    try:
        respond_addfd(notif.id, fd)
    finally:
        os.close(fd)


def handle_cow_stat(notif, nr: int, real_path: str,
                    id_valid, respond_val, respond_errno, respond_continue) -> None:
    """Do stat on the resolved COW path, write result to child's buffer."""
    nr_newfstatat = _SYSCALL_NR.get("newfstatat")
    nr_stat = _SYSCALL_NR.get("stat")
    nr_lstat = _SYSCALL_NR.get("lstat")

    if nr == nr_newfstatat:
        statbuf_addr = notif.data.args[2]
        use_lstat = bool(notif.data.args[3] & 0x100)  # AT_SYMLINK_NOFOLLOW
    elif nr == nr_stat:
        statbuf_addr = notif.data.args[1]
        use_lstat = False
    elif nr == nr_lstat:
        statbuf_addr = notif.data.args[1]
        use_lstat = True
    else:
        respond_continue(notif.id)
        return

    try:
        st = os.lstat(real_path) if use_lstat else os.stat(real_path)
    except OSError:
        respond_errno(notif.id, errno.ENOENT)
        return

    packed = struct.pack(
        "QQQIIIIQqqqQQQQQQqqq",
        st.st_dev, st.st_ino, st.st_nlink,
        st.st_mode, st.st_uid, st.st_gid, 0,
        st.st_rdev,
        st.st_size, st.st_blksize, st.st_blocks,
        int(st.st_atime), int(st.st_atime_ns % 1_000_000_000),
        int(st.st_mtime), int(st.st_mtime_ns % 1_000_000_000),
        int(st.st_ctime), int(st.st_ctime_ns % 1_000_000_000),
        0, 0, 0,
    )

    if not id_valid(notif.id):
        return

    try:
        write_bytes(notif.pid, statbuf_addr, packed)
        respond_val(notif.id, 0)
    except OSError:
        respond_continue(notif.id)


def handle_cow_readlink(notif, nr: int, target: str,
                        id_valid, respond_val, respond_continue) -> None:
    """Write readlink result to child's buffer."""
    nr_readlinkat = _SYSCALL_NR.get("readlinkat")

    if nr == nr_readlinkat:
        buf_addr = notif.data.args[2]
        bufsiz = notif.data.args[3] & 0xFFFFFFFF
    else:
        buf_addr = notif.data.args[1]
        bufsiz = notif.data.args[2] & 0xFFFFFFFF

    target_bytes = target.encode()
    write_len = min(len(target_bytes), bufsiz)

    if not id_valid(notif.id):
        return

    try:
        write_bytes(notif.pid, buf_addr, target_bytes[:write_len])
        respond_val(notif.id, write_len)
    except OSError:
        respond_continue(notif.id)


def handle_cow_getdents(notif, dir_path: str, cow_handler,
                        dir_cache: dict, id_valid, respond_val,
                        respond_continue, build_dirent64) -> None:
    """Handle getdents64 for COW directories — merge upper + lower entries."""
    pid = notif.pid
    child_fd_num = notif.data.args[0] & 0xFFFFFFFF
    buf_addr = notif.data.args[1]
    buf_size = notif.data.args[2] & 0xFFFFFFFF

    cache_key = ("cow", pid, child_fd_num)
    if cache_key not in dir_cache:
        workdir = cow_handler.workdir
        rel_path = os.path.relpath(dir_path, workdir)
        merged_names = cow_handler.list_merged_dir(rel_path)

        DT_DIR = 4
        DT_REG = 8
        DT_LNK = 10
        entries = []
        d_off = 0
        for name in merged_names:
            d_off += 1
            upper_p = cow_handler.upper_dir / rel_path / name
            lower_p = Path(workdir) / rel_path / name
            check = upper_p if upper_p.exists() else lower_p
            if check.is_dir():
                d_type = DT_DIR
            elif check.is_symlink():
                d_type = DT_LNK
            else:
                d_type = DT_REG
            entries.append(build_dirent64(d_off, d_off, d_type, name))

        dir_cache[cache_key] = entries

    entries = dir_cache[cache_key]

    if not id_valid(notif.id):
        return

    result = bytearray()
    consumed = 0
    for entry in entries:
        if len(result) + len(entry) > buf_size:
            break
        result.extend(entry)
        consumed += 1

    if consumed > 0:
        dir_cache[cache_key] = entries[consumed:]
    elif not entries:
        del dir_cache[cache_key]

    try:
        if result:
            write_bytes(pid, buf_addr, bytes(result))
        respond_val(notif.id, len(result))
    except OSError:
        dir_cache.pop(cache_key, None)
        respond_continue(notif.id)
