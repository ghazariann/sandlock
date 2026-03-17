# SPDX-License-Identifier: Apache-2.0
"""Deterministic randomness via seeded PRNG.

Intercepts getrandom() and returns deterministic bytes from a
seeded PRNG. Same seed = same output across runs.

Uses a simple xoshiro256** PRNG for speed. The PRNG state is
per-sandbox (shared across all processes in the sandbox).
"""

from __future__ import annotations

import struct

import os

from ._seccomp import _SYSCALL_NR
from ._procfs import write_bytes

NR_GETRANDOM = _SYSCALL_NR.get("getrandom")


class DeterministicRandom:
    """Seeded PRNG that replaces getrandom() output."""

    def __init__(self, seed: int):
        # Initialize xoshiro256** state from seed
        # Use splitmix64 to expand seed into 4 state words
        self._state = list(_splitmix64_init(seed))

    def generate(self, n: int) -> bytes:
        """Generate n deterministic random bytes."""
        result = bytearray()
        while len(result) < n:
            val = self._next()
            result.extend(struct.pack("<Q", val))
        return bytes(result[:n])

    def _next(self) -> int:
        """xoshiro256** next value."""
        s = self._state
        result = _rotl(s[1] * 5, 7) * 9
        result &= 0xFFFFFFFFFFFFFFFF

        t = (s[1] << 17) & 0xFFFFFFFFFFFFFFFF
        s[2] ^= s[0]
        s[3] ^= s[1]
        s[1] ^= s[2]
        s[0] ^= s[3]
        s[2] ^= t
        s[3] = _rotl(s[3], 45)

        return result


def _rotl(x: int, k: int) -> int:
    return ((x << k) | (x >> (64 - k))) & 0xFFFFFFFFFFFFFFFF


def _splitmix64_init(seed: int) -> tuple[int, int, int, int]:
    """Expand a seed into 4 state words via splitmix64."""
    def _next(s):
        s = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        z = z ^ (z >> 31)
        return s, z & 0xFFFFFFFFFFFFFFFF

    s = seed & 0xFFFFFFFFFFFFFFFF
    s, a = _next(s)
    s, b = _next(s)
    s, c = _next(s)
    s, d = _next(s)
    return (a, b, c, d)


def make_dev_random_fd(seed: int) -> int:
    """Create a pipe fd that yields infinite deterministic random bytes.

    Uses a separate PRNG stream (derived from seed) so it doesn't
    interfere with getrandom() output. A daemon thread feeds PRNG
    bytes into the pipe on demand via kernel backpressure.

    Returns the read end of the pipe (caller injects into child).
    """
    import threading

    # Derive a separate PRNG stream for /dev/urandom
    rng = DeterministicRandom(seed ^ 0x5F5F_4445_565F_5244)  # "__DEV_RD"

    read_fd, write_fd = os.pipe()

    def _feeder():
        try:
            while True:
                chunk = rng.generate(4096)
                try:
                    os.write(write_fd, chunk)
                except OSError:
                    break  # Pipe closed (child exited)
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass

    t = threading.Thread(target=_feeder, daemon=True)
    t.start()

    return read_fd


def handle_getrandom(notif, rng: DeterministicRandom,
                     id_valid, respond_val, respond_continue) -> None:
    """Handle getrandom(buf, buflen, flags) — return deterministic bytes."""
    buf_addr = notif.data.args[0]
    buflen = notif.data.args[1] & 0xFFFFFFFF

    if buflen == 0:
        respond_val(notif.id, 0)
        return

    # Cap at 256 bytes per call (kernel does same)
    buflen = min(buflen, 256)

    data = rng.generate(buflen)

    if not id_valid(notif.id):
        return

    try:
        write_bytes(notif.pid, buf_addr, data)
        respond_val(notif.id, len(data))
    except OSError:
        respond_continue(notif.id)
