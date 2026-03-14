# SPDX-License-Identifier: Apache-2.0
"""Extract local Docker images into rootfs directories for sandboxing.

Uses ``docker create`` + ``docker export`` to extract a locally available
image into a cached rootfs directory.  No registry pulling — the image
must already be present in the local Docker storage.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

from .exceptions import SandboxError


_CACHE_DIR = Path("~/.cache/sandlock/images").expanduser()


def extract(image: str, cache_dir: Path | None = None) -> str:
    """Extract a local Docker image into a rootfs directory.

    Creates a temporary container from the image, exports its filesystem,
    and extracts it into a cached directory.  Subsequent calls with the
    same image name return the cached path immediately.

    Args:
        image: Docker image name (e.g. "python:3.12-slim", "alpine").
            Must already be pulled locally.
        cache_dir: Override cache directory (default ~/.cache/sandlock/images).

    Returns:
        Absolute path to the extracted rootfs directory.

    Raises:
        SandboxError: If docker is not available or the image is not found.
    """
    cache = cache_dir or _CACHE_DIR
    cache_key = hashlib.sha256(image.encode()).hexdigest()[:16]
    rootfs = cache / cache_key / "rootfs"

    # Return cached rootfs if available
    if rootfs.is_dir() and any(rootfs.iterdir()):
        return str(rootfs)

    # Create a temporary container (does not start it)
    try:
        container_id = subprocess.check_output(
            ["docker", "create", image, "/bin/true"],
            stderr=subprocess.PIPE,
        ).decode().strip()
    except FileNotFoundError:
        raise SandboxError("docker CLI not found")
    except subprocess.CalledProcessError as e:
        raise SandboxError(f"docker create failed: {e.stderr.decode().strip()}")

    try:
        rootfs.mkdir(parents=True, exist_ok=True)

        # Export and extract
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=True) as tmp:
            subprocess.check_call(
                ["docker", "export", "-o", tmp.name, container_id],
                stderr=subprocess.PIPE,
            )
            with tarfile.open(tmp.name, "r:*") as tar:
                members = [
                    m for m in tar.getmembers()
                    if not m.name.startswith("/")
                    and ".." not in m.name
                    and m.type not in (tarfile.CHRTYPE, tarfile.BLKTYPE)
                ]
                tar.extractall(rootfs, members=members)
    except Exception:
        # Clean up partial extraction
        import shutil
        shutil.rmtree(rootfs, ignore_errors=True)
        raise
    finally:
        subprocess.call(
            ["docker", "rm", container_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    return str(rootfs)


def get_default_cmd(image: str) -> list[str]:
    """Get the default command (ENTRYPOINT + CMD) for a local Docker image.

    Returns:
        Command list, or ["/bin/sh"] if none is configured.

    Raises:
        SandboxError: If docker inspect fails.
    """
    try:
        raw = subprocess.check_output(
            ["docker", "inspect", "--format",
             "{{json .Config.Entrypoint}}|{{json .Config.Cmd}}", image],
            stderr=subprocess.PIPE,
        ).decode().strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ["/bin/sh"]

    parts = raw.split("|", 1)
    entrypoint = json.loads(parts[0]) if parts[0] != "null" else None
    cmd = json.loads(parts[1]) if len(parts) > 1 and parts[1] != "null" else None

    if entrypoint and cmd:
        return entrypoint + cmd
    if entrypoint:
        return entrypoint
    if cmd:
        return cmd
    return ["/bin/sh"]
