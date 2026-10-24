# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Seed inputs for each fuzz target, derived rather than committed.

The ingest seeds come from ``tests/fixtures/ingest_fixtures.json``, the same
records the parser tests use, so the corpus starts on every parser family and
cannot drift from the fixtures. Everything else is a handful of hand-written
shapes. No real host, address or person appears: addresses are loopback or the
RFC 5737 / RFC 3849 documentation ranges.

    python -m tests.fuzz.seeds normalize corpus/   # writes seed-000, seed-001, ...
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ingest.normalize import normalize
from store.schema import canonical_json

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ingest_fixtures.json"

_TEXT_LINES = (
    'type=EXECVE msg=audit(1755162662.451:8891): argc=3 a0="/bin/bash" a1="-c" a2="id"',
    "type=USER_AUTH msg=audit(1755162662.452:8892): pid=2211 uid=0 msg='op=PAM:auth acct=\"svc\" res=success'",
    'level=info ts=2026-08-14T09:40:00Z msg="session opened" user=svc-backup src=192.0.2.4',
    "Aug 14 09:40:00 app-web-01 sshd[2211]: Accepted publickey for svc-backup from 192.0.2.4 port 50122",
    '{"truncated": "mid-write',
    "[1, 2, 3]",
)

_EGRESS_CANDIDATES = (
    ("127.0.0.1", 8443),
    ("::1", 8443),
    ("0:0:0:0:0:0:0:1", 8443),
    ("192.0.2.10", 443),
    ("2001:db8::10", 443),
    ("::ffff:127.0.0.1", 443),
    ("169.254.169.254", 80),
    ("fe80::1%2", 443),
    ("0.0.0.0", 80),  # noqa: S104 - refused by the control under test, not a bind address
    ("224.0.0.1", 80),
    ("255.255.255.255", 80),
    ("not-an-ip", 80),
    ("127.0.0.1", 0),
)

#: Whole allow-list files: the shipped default, one declared loopback host, and
#: the three shapes that escaped ``EgressAllowlist.load`` as a foreign exception
#: before the loader caught them. The depth bomb is past ``json``'s limit on
#: 3.11 to 3.14 and under the workflow's ``-max_len``.
_ALLOWLISTS = (
    b'{"version": 1, "hosts": []}',
    b'{"version": 1, "hosts": [{"address": "127.0.0.1", "port": 8443,'
    b' "authorization": "fuzz seed: loopback"}]}',
    b'{"hosts": ["\xff"]}',
    b"[" * 50_000,
    b'{"version": ' + b"9" * 5000 + b"}",
)


def _records() -> list[dict[str, Any]]:
    fixtures = json.loads(_FIXTURES.read_text(encoding="utf-8"))
    return [fixtures[name]["record"] for name in sorted(fixtures)]


def seeds(target: str) -> list[bytes]:
    """Return the seed inputs for ``target``; raise ``KeyError`` for an unknown one."""
    if target == "normalize":
        records = [json.dumps(record, sort_keys=True).encode() for record in _records()]
        return records + [line.encode() for line in _TEXT_LINES]
    if target == "keyvalue":
        return [line.encode() for line in _TEXT_LINES]
    if target == "allowlist":
        return list(_ALLOWLISTS)
    if target == "egress":
        return [port.to_bytes(2, "big") + text.encode() for text, port in _EGRESS_CANDIDATES]
    if target == "projection":
        return [canonical_json(normalize(record).to_dict()).encode() for record in _records()]
    raise KeyError(target)


def main(argv: list[str]) -> int:
    """Write ``target``'s seeds into ``directory`` as ``seed-NNN`` files."""
    if len(argv) != 3:
        print("usage: python -m tests.fuzz.seeds <target> <directory>", file=sys.stderr)
        return 2
    target, directory = argv[1], Path(argv[2])
    try:
        inputs = seeds(target)
    except KeyError:
        print(f"unknown fuzz target: {target}", file=sys.stderr)
        return 2
    directory.mkdir(parents=True, exist_ok=True)
    for index, data in enumerate(inputs):
        (directory / f"seed-{index:03d}").write_bytes(data)
    print(f"wrote {len(inputs)} seeds for {target} to {directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
