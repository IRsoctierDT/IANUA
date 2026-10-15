#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Scheduled maintenance for the tamper-evident audit log (Hardening #2).

Verifies the hash chain and its head signature, then applies the size/rotation
+ retention policy on demand. Intended to be run by a scheduler; it is
idempotent and appends no entries, so the chain head and its signature are
unchanged.

The signature scheme is resolved by :func:`agents.policies.audit.verifier_from_env`
— ``AUDIT_HMAC_KEY``, else ``AUDIT_ED25519_PUBLIC_KEY``, else chain-only. That is
the *same* resolution :mod:`scripts.audit_verify` uses, deliberately: this job
rotates and prunes, so it must not proceed on a log the read-only verifier would
reject.

Fail-closed, in two ways:

* **A log that does not verify is not rotated**, and the process exits non-zero,
  so a compromised or corrupted log is surfaced rather than silently rotated away.
* **A path with no log at it is a failure, not a no-op** — exit ``2``, the same
  code and ``failure`` text :mod:`scripts.audit_verify` uses, and nothing is
  created at that path. Rotation and pruning delete evidence; a scheduled job
  pointed at a wrong or vanished path must not report success for work it did
  not do. This check is **not** skipped by ``--no-verify``, which opts out of
  verifying a chain, not out of having one.

There is one chain per subsystem rather than one global log, so a corrupted
chain in one cannot invalidate another: maintain each path that is actually
written — ``data/collect/audit.log``, ``data/events/audit.log``,
``data/pipeline/audit.log``, ``data/compliance/audit.log``.

Usage::

    python -m scripts.audit_maintenance --log data/pipeline/audit.log \\
        --max-bytes 10485760 --retain-segments 30
    # key material (optional) comes from the environment, never a flag:
    AUDIT_HMAC_KEY=... python -m scripts.audit_maintenance --log ...
    # an Ed25519-signed chain verifies with only the public key:
    AUDIT_ED25519_PUBLIC_KEY=... python -m scripts.audit_maintenance --log ...

Schedule examples::

    # crontab: nightly at 02:30, one invocation per chain
    30 2 * * *  cd /srv/ianua && AUDIT_HMAC_KEY=$(cat /etc/ianua/audit.key) \\
        python -m scripts.audit_maintenance --log data/pipeline/audit.log \\
        --max-bytes 10485760 --retain-segments 30 >> data/audit-maint.log 2>&1

    # systemd timer: an OnCalendar=daily unit running the same command.

Repeat the line per chain (or wrap the four in one shell loop); a non-zero exit
from any of them must fail the job, which is the point of exiting ``2`` on a
path that holds no log.

Exit codes: ``0`` ok · ``2`` verification failed — including a **nonexistent
log** (no active file, archives, or checkpoint at the given path) · ``3`` bad
arguments or key material.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agents.policies.audit import AuditLogger, verifier_from_env


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
        help=(
            "Skip chain/signature verification before applying retention (not "
            "recommended). The existence check still applies: a path holding no "
            "log exits 2 either way."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = _parse_args(argv)
    try:
        signer = verifier_from_env()
    except (ValueError, RuntimeError) as exc:
        # Bad hex key, or Ed25519 requested without the crypto extra. Refused
        # rather than ignored: key material that exists but cannot be used must
        # not degrade into a chain-only check that then rotates the log.
        print(f"error: invalid signing configuration: {exc}", file=sys.stderr)
        return 3
    try:
        logger = AuditLogger(
            args.log,
            max_bytes=args.max_bytes,
            retain_segments=args.retain_segments,
            signer=signer,
        )
    except ValueError as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return 3

    if not logger.exists():
        # Checked before ``--no-verify`` is honored and before
        # ``apply_retention()``, whose ``mkdir(parents=True)`` would otherwise
        # build the entire wrong path and report success for it. An empty log
        # that *exists* still verifies as intact and is maintained normally;
        # this is only the case where nothing was ever logged here.
        print(
            json.dumps(
                {
                    "log": str(args.log),
                    "verified": False,
                    "action": "aborted",
                    "failure": "audit log not found",
                }
            ),
            file=sys.stderr,
        )
        return 2

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
