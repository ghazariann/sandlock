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

import struct
import threading
from dataclasses import dataclass, field

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
