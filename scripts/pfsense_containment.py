#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Issue approvals and run pfSense containment — stage 8, phase 3.

Three subcommands, in the order an operator uses them:

``issue``
    Sign one approval with the approver's private key and print the token.
    The key is read from ``IANUA_APPROVER_KEY`` (hex) and removed from the
    process environment immediately; populate it for one command only, e.g.
    from the macOS Keychain. Touches no network and writes no file.
``probe``
    Read-only: confirm both aliases resolve on the declared firewall. Needs the
    ``pfsense:probe`` grant. Run it before the first ``send``.
``send``
    Read an approval token on stdin, verify and consume it, and apply the change.
    Needs the ``pfsense:send`` grant, the firewall declared in both local files,
    and ``IANUA_PFSENSE_API_KEY``.

Exit codes: ``0`` done · ``1`` refused or failed, nothing changed · ``3`` not
granted by the policy bundle · ``4`` the change was sent and its outcome is
unknown — check the alias on the firewall before retrying.

Security considerations: no secret is accepted on the command line (argv is
visible in the process list); every refusal is printed through
:func:`scripts._terminal.printable`, because some of its text originates on the
firewall; and the audit chain is signed with whatever scheme the node is
configured for, via :func:`agents.policies.audit.signer_from_env`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

from agents.policies import execution_approval as ea  # noqa: E402
from agents.policies.audit import AuditLogger, signer_from_env  # noqa: E402
from agents.policies.bundle import DEFAULT_BUNDLE_PATH, PolicyBundleError, load_bundle  # noqa: E402
from agents.policies.egress import EgressAllowlist, EgressAllowlistError  # noqa: E402
from agents.policies.signing import Ed25519Signer  # noqa: E402
from agents.tools import pfsense_live as live  # noqa: E402
from scripts._terminal import escape_unencodable, printable  # noqa: E402

APPROVER_KEY_ENV = "IANUA_APPROVER_KEY"
DEFAULT_LEDGER = REPO_ROOT / "data" / "containment" / "approvals.ledger"
DEFAULT_AUDIT = REPO_ROOT / "data" / "containment" / "audit.log"
MAX_TOKEN_BYTES = ea.MAX_TOKEN_BYTES

EXIT_OK, EXIT_REFUSED, EXIT_NOT_GRANTED, EXIT_UNKNOWN = 0, 1, 3, 4


def _fail(message: str, code: int = EXIT_REFUSED) -> int:
    print(f"refused: {printable(message)}", file=sys.stderr)
    return code


def _action_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--capability", required=True, choices=sorted(ea.CAPABILITIES))
    parser.add_argument("--target", required=True, help="one canonical IP literal")
    parser.add_argument("--plan", required=True, help="plan id, e.g. plan-0123456789abcdef")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    issue = sub.add_parser("issue", help="sign one approval (key from IANUA_APPROVER_KEY)")
    _action_args(issue)
    issue.add_argument("--approver", required=True, help="your id in approvers.json")
    issue.add_argument(
        "--ttl", type=int, default=300, help=f"seconds, at most {ea.MAX_TTL_SECONDS}"
    )

    for name, text in (("probe", "read-only alias check"), ("send", "apply an approved change")):
        command = sub.add_parser(name, help=text)
        command.add_argument("--config", type=Path, default=live.DEFAULT_LOCAL_CONFIG)
        command.add_argument("--egress", type=Path, default=live.DEFAULT_LOCAL_EGRESS)
        command.add_argument("--policy", type=Path, default=DEFAULT_BUNDLE_PATH)
        command.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
        if name == "send":
            _action_args(command)
            command.add_argument("--approvers", type=Path, default=ea.DEFAULT_APPROVERS)
            command.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    return parser


def _issue(args: argparse.Namespace) -> int:
    key = os.environ.pop(APPROVER_KEY_ENV, "")
    try:
        signer = Ed25519Signer(bytes.fromhex(key))
    except (ValueError, RuntimeError):
        # RuntimeError: the optional cryptography extra is not installed.
        return _fail(f"{APPROVER_KEY_ENV} is unset or not a 32-byte hex Ed25519 private key")
    try:
        token = ea.issue_approval(
            signer,
            approver=args.approver,
            capability=args.capability,
            target=args.target,
            plan_id=args.plan,
            ttl_seconds=args.ttl,
        )
    except ea.ApprovalError as exc:
        return _fail(str(exc))
    print(token)
    return EXIT_OK


def _client(args: argparse.Namespace) -> live.PfSenseLive:
    target, config = live.load_local_config(args.config)
    return live.PfSenseLive(
        target,
        config,
        engine=load_bundle(args.policy),
        egress=EgressAllowlist.load(args.egress),
        audit=AuditLogger(args.audit, signer=signer_from_env()),
    )


def _run(args: argparse.Namespace) -> int:
    try:
        client = _client(args)
    except (live.LiveError, PolicyBundleError, EgressAllowlistError, OSError, ValueError) as exc:
        return _fail(f"configuration unusable: {exc}")
    try:
        if args.command == "probe":
            result: dict[str, object] = {"aliases": client.probe()}
        else:
            token = sys.stdin.read(MAX_TOKEN_BYTES + 1).strip()
            approval = ea.authorize(
                token,
                capability=args.capability,
                target=args.target,
                plan_id=args.plan,
                approvers=ea.load_approvers(args.approvers),
                ledger=ea.ApprovalLedger(args.ledger),
                audit=client.audit,
            )
            result = client.send(approval)
    except live.OutcomeUnknownError as exc:
        return _fail(str(exc), EXIT_UNKNOWN)
    except live.NotGrantedError as exc:
        return _fail(str(exc), EXIT_NOT_GRANTED)
    except live.LiveError as exc:
        return _fail(str(exc))
    except ea.ApprovalError as exc:
        return _fail(f"approval: {exc}")
    print(json.dumps(result, sort_keys=True))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch; returns the process exit code."""
    escape_unencodable()
    args = _build_parser().parse_args(argv)
    if args.command == "issue":
        return _issue(args)
    return _run(args)


if __name__ == "__main__":
    sys.exit(main())
