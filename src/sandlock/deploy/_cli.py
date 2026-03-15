# SPDX-License-Identifier: Apache-2.0
"""CLI handler for ``sandlock deploy``."""

from __future__ import annotations

import argparse
import sys


def _resolve_target(args: argparse.Namespace):
    """Resolve a target from sandlock.toml or CLI flags.

    If args.host looks like a target name (no '@' or '.'), try loading
    it from sandlock.toml first.  CLI flags override target fields.
    """
    from ._target import load_target, Target

    host = args.host
    target = None

    # Try loading as a named target if it doesn't look like a host
    if "@" not in host and "." not in host:
        try:
            target = load_target(host)
        except (FileNotFoundError, KeyError):
            pass

    if target is not None:
        # CLI flags override target config
        return dict(
            host=target.host,
            port=args.port if args.port != 22 else target.port,
            key=args.key or target.key,
            profile=args.profile or target.profile,
            pubkey=getattr(args, "pubkey", None) or target.pubkey,
            force_command=args.force_command or target.force_command,
            remote_python=(args.remote_python if args.remote_python != "python3"
                           else target.remote_python),
            repo=target.repo,
            branch=target.branch,
            workdir=target.workdir,
            setup=target.setup,
        )

    # Plain host — use CLI flags only
    return dict(
        host=host,
        port=args.port,
        key=args.key,
        profile=args.profile,
        pubkey=getattr(args, "pubkey", None),
        force_command=args.force_command,
        remote_python=args.remote_python,
        repo=None,
        branch=None,
        workdir=None,
        setup=None,
    )


def run_deploy(args: argparse.Namespace) -> int:
    """Entry point for the deploy subcommand."""
    from ._ssh import SSHSession
    from ._remote import deploy, verify

    try:
        conf = _resolve_target(args)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Parse user@host
    host_str = conf["host"]
    if "@" in host_str:
        user, host = host_str.split("@", 1)
    else:
        user, host = None, host_str

    session = SSHSession(
        host=host,
        user=user,
        port=conf["port"],
        key_file=conf["key"],
    )

    try:
        sandlock_bin = deploy(
            session,
            profile=conf["profile"],
            pubkey=conf["pubkey"],
            force_command=conf["force_command"],
            remote_python=conf["remote_python"],
            repo=conf["repo"],
            branch=conf["branch"],
            workdir=conf["workdir"],
            setup=conf["setup"],
        )

        if not args.no_verify:
            if not verify(session, sandlock_bin):
                return 1

        print("\nDeployment complete.")
        return 0

    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        session.close()
