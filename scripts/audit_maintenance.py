#!/usr/bin/env python3
"""Scheduled maintenance for the tamper-evident audit log (Hardening #2).

Verifies the hash chain (and its HMAC head signature, if ``AUDIT_HMAC_KEY`` is
set), then applies the size/rotation + retention policy on demand. Intended to be
run by a scheduler; it is idempotent and appends no entries, so the chain head
and its signature are unchanged.

Fail-closed: if verification fails the policy is **not** applied and the process
exits non-zero, so a compromised or corrupted log is surfaced rather than
silently rotated away.

Usage::

    python -m scripts.audit_maintenance --log data/audit.log \\
        --max-bytes 10485760 --retain-segments 30
    # signing key (optional) comes from the environment:
    AUDIT_HMAC_KEY=... python -m scripts.audit_maintenance --log data/audit.log ...

Schedule examples::

    # crontab: nightly at 02:30
    30 2 * * *  cd /srv/app && AUDIT_HMAC_KEY=$(cat /etc/app/audit.key) \\
        python -m scripts.audit_maintenance --log data/audit.log \\
        --max-bytes 10485760 --retain-segments 30 >> data/audit-maint.log 2>&1

    # systemd timer: an OnCalendar=daily unit running the same command.

Exit codes: ``0`` ok · ``2`` verification failed · ``3`` bad arguments.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agents.policies.audit import AuditLogger, signing_key_from_env


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True, help="Path to the active audit log.")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="Rotate the active log once it reaches this size (bytes).",
    )
    parser.add_argument(
        "--retain-segments",
        type=int,
        default=None,
        help="Keep at most this many archived segments (older ones are pruned).",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip chain/signature verification before applying retention (not recommended).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = _parse_args(argv)
    try:
        logger = AuditLogger(
            args.log,
            max_bytes=args.max_bytes,
            retain_segments=args.retain_segments,
            signing_key=signing_key_from_env(),
        )
    except ValueError as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return 3

    verified: bool | None = None
    if not args.no_verify:
        verified = logger.verify()
        if not verified:
            print(
                json.dumps({"log": str(args.log), "verified": False, "action": "aborted"}),
                file=sys.stderr,
            )
            return 2  # fail closed: do not rotate a log that does not verify

    summary = logger.apply_retention()
    print(json.dumps({"log": str(args.log), "verified": verified, **summary}))
    return 0


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    raise SystemExit(main())
