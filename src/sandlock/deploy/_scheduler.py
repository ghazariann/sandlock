# SPDX-License-Identifier: Apache-2.0
"""Cluster scheduler: probe nodes, pick lightest, run.

Probes are cached locally (~/.cache/sandlock/) with a configurable TTL
to avoid SSH overhead on every schedule call. No daemon, no persistent state.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

from ._ssh import SSHSession
from ._target import Cluster, Target, load_cluster, load_target

CACHE_DIR = Path("~/.cache/sandlock").expanduser()
DEFAULT_TTL = 30  # seconds


@dataclass
class NodeStatus:
    """Resource snapshot from a single node."""
    name: str
    host: str
    load_1m: float
    mem_available_mb: int
    cpus: int
    reachable: bool
    error: str | None = None
    ts: float = 0.0


def _cache_path(cluster_name: str) -> Path:
    return CACHE_DIR / f"cluster_{cluster_name}.json"


def _read_cache(cluster_name: str, ttl: float = DEFAULT_TTL) -> list[NodeStatus] | None:
    """Read cached probe results if fresh enough."""
    path = _cache_path(cluster_name)
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    now = time.time()
    statuses = []
    for entry in data:
        if now - entry.get("ts", 0) > ttl:
            return None  # any stale entry invalidates the whole cache
        statuses.append(NodeStatus(**entry))

    return statuses


def _write_cache(cluster_name: str, statuses: list[NodeStatus]) -> None:
    """Write probe results to cache."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        data = [asdict(s) for s in statuses]
        _cache_path(cluster_name).write_text(json.dumps(data))
    except OSError:
        pass  # cache is best-effort


def probe_node(target: Target) -> NodeStatus:
    """SSH into a node and collect load, memory, CPU count."""
    user, host = (target.host.split("@", 1) if "@" in target.host
                  else (None, target.host))
    session = SSHSession(
        host=host, user=user, port=target.port, key_file=target.key,
    )
    try:
        session.connect()

        # Single command: load, available mem, cpu count
        rc, out, _ = session.exec(
            "cat /proc/loadavg && "
            "awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo && "
            "nproc"
        )
        if rc != 0:
            return NodeStatus(
                name=target.name, host=target.host,
                load_1m=999, mem_available_mb=0, cpus=0,
                reachable=False, error="probe command failed",
                ts=time.time(),
            )

        lines = out.strip().splitlines()
        load_1m = float(lines[0].split()[0])
        mem_available_mb = int(lines[1])
        cpus = int(lines[2])

        return NodeStatus(
            name=target.name, host=target.host,
            load_1m=load_1m, mem_available_mb=mem_available_mb,
            cpus=cpus, reachable=True,
            ts=time.time(),
        )
    except Exception as e:
        return NodeStatus(
            name=target.name, host=target.host,
            load_1m=999, mem_available_mb=0, cpus=0,
            reachable=False, error=str(e),
            ts=time.time(),
        )
    finally:
        session.close()


def probe_cluster(cluster_name: str, ttl: float = DEFAULT_TTL) -> list[NodeStatus]:
    """Probe all nodes in a cluster in parallel.

    Uses cached results if available and within TTL.
    """
    cluster = load_cluster(cluster_name)
    targets = [load_target(node) for node in cluster.nodes]

    with ThreadPoolExecutor(max_workers=len(targets)) as pool:
        futures = {pool.submit(probe_node, t): t for t in targets}
        results = []
        for future in as_completed(futures):
            results.append(future.result())

    _write_cache(cluster_name, results)
    return results


def probe_cluster_cached(cluster_name: str, ttl: float = DEFAULT_TTL) -> list[NodeStatus]:
    """Return cached probe results if fresh, otherwise probe and cache."""
    cached = _read_cache(cluster_name, ttl)
    if cached is not None:
        return cached
    return probe_cluster(cluster_name, ttl)


def pick_node(statuses: list[NodeStatus]) -> NodeStatus | None:
    """Pick the node with the lowest load (normalized by CPU count)."""
    reachable = [s for s in statuses if s.reachable]
    if not reachable:
        return None
    # Lowest load-per-cpu wins
    return min(reachable, key=lambda s: s.load_1m / max(s.cpus, 1))


def schedule(cluster_name: str, ttl: float = DEFAULT_TTL) -> Target:
    """Pick the best node using cached probes, then return its target.

    Raises:
        RuntimeError: If no nodes are reachable.
    """
    statuses = probe_cluster_cached(cluster_name, ttl)
    best = pick_node(statuses)
    if best is None:
        unreachable = ", ".join(s.name for s in statuses)
        raise RuntimeError(f"no reachable nodes in cluster '{cluster_name}': {unreachable}")
    return load_target(best.name)
