# SPDX-License-Identifier: Apache-2.0
"""Transparent TCP port remapping via seccomp user notification.

Each sandbox gets a slice of the ``net_bind`` port range.  When the
app calls bind() on a virtual port, the supervisor rewrites the
sockaddr in the child's memory to use the next available real port
from its slice, then lets the syscall proceed.  connect() is remapped
the same way so sandbox-to-sandbox traffic works transparently.

The ``net_bind`` range serves double duty: Landlock restricts binding
to only those ports (security), and the PortAllocator slices them
across sandboxes (isolation).

Requires Linux 5.9+ (SECCOMP_USER_NOTIF_FLAG_CONTINUE + /proc/pid/mem
write access).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import struct
import threading
from dataclasses import dataclass, field

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# pidfd_getfd(2) syscall number
_NR_PIDFD_GETFD = 438  # x86_64 and aarch64 (asm-generic)

_AF_INET = 2
_AF_INET6 = 10
_PORT_OFFSET = 2  # sin_port / sin6_port at byte offset 2


@dataclass
class PortMap:
    """Bidirectional mapping between virtual and real ports.

    The pool is a slice of real ports assigned by the PortAllocator.
    Thread-safe.
    """

    pool: list[int]
    """Slice of real ports assigned to this sandbox."""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _pool_set: set[int] = field(default_factory=set, init=False, repr=False)
    _virtual_to_real: dict[int, int] = field(default_factory=dict, repr=False)
    _real_to_virtual: dict[int, int] = field(default_factory=dict, repr=False)
    _next_index: int = field(default=0, repr=False)

    def __post_init__(self):
        self._pool_set = set(self.pool)

    def real_port(self, virtual: int) -> int | None:
        """Get or allocate the real port for a virtual port.

        If the virtual port is already in the pool (it's a real port),
        returns it unchanged -- no remapping needed.
        Returns None if the pool is exhausted.
        """
        with self._lock:
            if virtual in self._pool_set:
                return virtual  # Already a real port, pass through
            if virtual in self._virtual_to_real:
                return self._virtual_to_real[virtual]
            if self._next_index >= len(self.pool):
                return None
            real = self.pool[self._next_index]
            self._next_index += 1
            self._virtual_to_real[virtual] = real
            self._real_to_virtual[real] = virtual
            return real

    def virtual_port(self, real: int) -> int | None:
        """Look up the virtual port for a real port, or None."""
        with self._lock:
            return self._real_to_virtual.get(real)


class PortAllocator:
    """Slices a port pool across sandboxes.

    Given the full ``net_bind`` port list, each call to ``allocate()``
    returns a non-overlapping slice.  Thread-safe.
    """

    def __init__(self, ports: list[int], per_sandbox: int = 100):
        self._ports = ports
        self._per_sandbox = per_sandbox
        self._next = 0
        self._lock = threading.Lock()

    def allocate(self) -> PortMap:
        """Return a PortMap backed by the next available slice."""
        with self._lock:
            start = self._next
            end = min(start + self._per_sandbox, len(self._ports))
            self._next = end
        return PortMap(pool=self._ports[start:end])


# Cache allocators by the frozenset of ports so all sandboxes with
# the same net_bind share one allocator.
_allocators: dict[frozenset[int], PortAllocator] = {}
_allocators_lock = threading.Lock()


def get_port_map(bind_ports: list[int]) -> PortMap:
    """Get a PortMap slice for a sandbox from the shared allocator.

    All sandboxes with the same ``net_bind`` range share one allocator,
    ensuring non-overlapping slices.
    """
    key = frozenset(bind_ports)
    with _allocators_lock:
        if key not in _allocators:
            _allocators[key] = PortAllocator(sorted(bind_ports))
        return _allocators[key].allocate()


def _read_port(pid: int, sockaddr_addr: int, addrlen: int) -> int | None:
    """Read the port from a sockaddr in child memory.

    Returns the port number, or None if not AF_INET/AF_INET6.
    """
    from ._procfs import read_bytes

    if addrlen < 4:
        return None

    data = read_bytes(pid, sockaddr_addr, min(addrlen, 28))
    family = struct.unpack_from("H", data, 0)[0]

    if family not in (_AF_INET, _AF_INET6):
        return None

    return struct.unpack_from("!H", data, _PORT_OFFSET)[0]


def _remap_sockaddr(pid: int, sockaddr_addr: int, addrlen: int,
                    port_map: PortMap) -> bool:
    """Rewrite the port in a sockaddr to a real port from the pool.

    Returns True if remapped, False if not applicable.
    """
    from ._procfs import read_bytes, write_bytes

    if addrlen < 4:
        return False

    data = read_bytes(pid, sockaddr_addr, min(addrlen, 28))
    family = struct.unpack_from("H", data, 0)[0]

    if family not in (_AF_INET, _AF_INET6):
        return False

    virtual_port = struct.unpack_from("!H", data, _PORT_OFFSET)[0]
    if virtual_port == 0:
        return False  # Ephemeral port

    real = port_map.real_port(virtual_port)
    if real is None:
        return False  # Pool exhausted
    if real == virtual_port:
        return False  # Already a real port, no rewrite needed

    write_bytes(pid, sockaddr_addr + _PORT_OFFSET, struct.pack("!H", real))
    return True


def fixup_getsockname(pid: int, sockaddr_addr: int, addrlen_addr: int,
                      fd: int, port_map: PortMap) -> bool:
    """Perform getsockname() in the supervisor and rewrite real port to virtual.

    We can't use CONTINUE because getsockname() fills the sockaddr
    after the syscall, and we need to post-process it.  Instead, we
    duplicate the child's socket via pidfd_getfd, do getsockname()
    in supervisor space, rewrite real->virtual port, and write the
    result into the child's memory.

    Returns True if handled, False if not applicable.
    """
    import os
    import socket as sock_mod
    from ._procfs import write_bytes

    # Duplicate the child's socket fd via pidfd_getfd syscall
    try:
        pidfd = os.pidfd_open(pid)
    except OSError:
        return False

    try:
        local_fd = _libc.syscall(
            ctypes.c_long(_NR_PIDFD_GETFD),
            ctypes.c_int(pidfd),
            ctypes.c_int(fd),
            ctypes.c_uint(0),
        )
        if local_fd < 0:
            return False
    finally:
        os.close(pidfd)

    try:
        s = sock_mod.socket(fileno=local_fd)
        try:
            addr = s.getsockname()
            family = s.family
        finally:
            s.detach()
    except OSError:
        os.close(local_fd)
        return False

    if family not in (sock_mod.AF_INET, sock_mod.AF_INET6):
        return False

    real_port = addr[1]
    virtual = port_map.virtual_port(real_port)
    if virtual is None:
        virtual = real_port  # Not remapped, use as-is

    # Build the sockaddr to write back
    # sa_family is host byte order (H), sin_port is network byte order (!H)
    if family == sock_mod.AF_INET:
        ip_bytes = sock_mod.inet_aton(addr[0])
        sockaddr = struct.pack("H", family)
        sockaddr += struct.pack("!H", virtual)
        sockaddr += ip_bytes
        sockaddr += b"\x00" * 8  # sin_zero
        written_len = 16
    else:
        ip_bytes = sock_mod.inet_pton(sock_mod.AF_INET6, addr[0])
        flowinfo = addr[2] if len(addr) > 2 else 0
        scope_id = addr[3] if len(addr) > 3 else 0
        sockaddr = struct.pack("H", family)
        sockaddr += struct.pack("!H", virtual)
        sockaddr += struct.pack("!I", flowinfo)
        sockaddr += ip_bytes
        sockaddr += struct.pack("!I", scope_id)
        written_len = 28

    # Write sockaddr and addrlen into child's memory
    try:
        write_bytes(pid, sockaddr_addr, sockaddr)
        write_bytes(pid, addrlen_addr, struct.pack("I", written_len))
    except OSError:
        return False

    return True
