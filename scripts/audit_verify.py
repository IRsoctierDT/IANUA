#!/usr/bin/env python3
"""Standalone verifier for the tamper-evident audit log (Hardening #2).

Recomputes the full hash chain across all retained segments (archives +
active log + ``.checkpoint`` anchoring) and reports a **structured diagnosis**
(`AuditLogger.verify_report`): entry/segment counts, the chain head, the head
signature's status, and — on failure — the first broken segment, line, and kind
of break. Read-only, deterministic, no network access; it never appends,
rotates, or rewrites anything.

Signature verification (auto-detected from the environment):

* ``AUDIT_HMAC_KEY`` — symmetric HMAC-SHA256 (the verifier holds the secret).
* ``AUDIT_ED25519_PUBLIC_KEY`` — asymmetric Ed25519 with **only the public
  key** (requires the ``.[crypto]`` extra): an auditor or CI can verify a log
  signed elsewhere without ever holding a key that could forge it.
* Neither set — chain-only verification (report says ``unsigned``); pass
  ``--require-signature`` to refuse that (fail closed for CI/cron use).

Usage::

    python -m scripts.audit_verify --log data/audit.log
    AUDIT_ED25519_PUBLIC_KEY=... python -m scripts.audit_verify \\
        --log data/audit.log --require-signature

    # CI/cron: JSON report on stdout; non-zero exit on any failure.

Exit codes: ``0`` intact · ``2`` verification failed — including a
**nonexistent log** (no active file, archives, or checkpoint at the given
path), so a monitor watching a wrong or vanished file cannot stay green ·
``3`` bad arguments / configuration (e.g. ``--require-signature`` with no key
material available).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from agents.policies.audit import AuditLogger, signing_key_from_env
from agents.policies.signing import Signer, ed25519_verifier_from_env


def _resolve_signer() -> Signer | None:
    """Pick the verification scheme from the environment (HMAC, else Ed25519).

    HMAC wins when both are set (it can also detect a wrong shared key), and the
    Ed25519 path needs only the *public* key — safe to hand to auditors/CI.
    """
    hmac_key = signing_key_from_env()
    if hmac_key is not None:
        from agents.policies.signing import HmacSigner

        return HmacSigner(hmac_key)
    return ed25519_verifier_from_env()


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True, help="Path to the active audit log.")
    parser.add_argument(
        "--require-signature",
        action="store_true",
        help=(
            "Fail (exit 3) unless key material is available and the head "
            "signature verifies — chain-only verification is refused."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = _parse_args(argv)
    try:
        signer = _resolve_signer()
    except (ValueError, RuntimeError) as exc:
        # Bad hex key, or Ed25519 requested without the crypto extra installed.
        print(f"error: invalid signing configuration: {exc}", file=sys.stderr)
        return 3
    if args.require_signature and signer is None:
        print(
            "error: --require-signature set but neither AUDIT_HMAC_KEY nor "
            "AUDIT_ED25519_PUBLIC_KEY is available.",
            file=sys.stderr,
        )
        return 3

    logger = AuditLogger(args.log, signer=signer)
    if not logger.exists():
        # A monitor pointed at a missing/wrong path must not stay green: a
        # nonexistent log (no active file, no archives, no checkpoint) is a
        # verification failure, distinct from an intentionally empty existing
        # log, which verifies as intact.
        print(json.dumps({"log": str(args.log), "intact": False, "failure": "audit log not found"}))
        return 2

    report = logger.verify_report()
    print(json.dumps({"log": str(args.log), **asdict(report)}))
    return 0 if report.intact else 2


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    raise SystemExit(main())
