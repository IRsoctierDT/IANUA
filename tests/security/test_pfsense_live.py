# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the live pfSense transport (stage 8, phase 3).

Driven against a real HTTPS stub on 127.0.0.1 with a certificate generated per
test, so pinning, the request bytes and the failure modes are exercised over a
real TLS socket rather than a mock. Every approval comes from the real
``authorize``. The stub records every request it receives, which is how "nothing
was sent" is asserted rather than assumed.
"""

from __future__ import annotations

import datetime
import hashlib
import http.server
import ipaddress
import json
import os
import ssl
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agents.policies import execution_approval as ea
from agents.policies.approval import PolicyEngine
from agents.policies.audit import AuditLogger
from agents.policies.egress import EgressAllowlist, LabHost, parse_address
from agents.policies.signing import Ed25519Signer, generate_ed25519_keypair
from agents.tools import pfsense_live as live
from agents.tools.pfsense import PfSenseConfig

_PLAN = "plan-0123456789abcdef"
_KEY = "k" * 40
_GRANTS = (live.SEND_LABEL, live.PROBE_LABEL)


@dataclass
class Firewall:
    """What the stub serves and what it saw."""

    aliases: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {"id": 3, "name": "IANUA_BLOCK", "type": "host", "address": []},
            {"id": 4, "name": "IANUA_ISOLATE", "type": "host", "address": []},
        ]
    )
    patch_status: int = 200
    drop_patch: bool = False
    oversized: bool = False
    ignore_filter: bool = False
    seen: list[dict[str, Any]] = field(default_factory=list)


def _certificate(directory: Path) -> tuple[Path, Path, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pfSense test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pin = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return cert_path, key_path, pin


def _handler(state: Firewall) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:  # silence the stub
            return

        def _reply(self, status: int, document: dict[str, Any]) -> None:
            body = json.dumps(document).encode()
            if state.oversized:
                body = b'{"pad":"' + b"x" * (live.MAX_RESPONSE_BYTES + 10) + b'"}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            state.seen.append(
                {"method": "GET", "path": self.path, "key": self.headers.get("X-API-Key")}
            )
            name = self.path.split("name=", 1)[1] if "name=" in self.path else ""
            data = [a for a in state.aliases if state.ignore_filter or a.get("name") == name]
            self._reply(200, {"code": 200, "status": "ok", "response_id": "SUCCESS", "data": data})

        def do_PATCH(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            state.seen.append(
                {
                    "method": "PATCH",
                    "path": self.path,
                    "body": body,
                    "key": self.headers.get("X-API-Key"),
                }
            )
            if state.drop_patch:
                self.close_connection = True
                return
            ok = state.patch_status == 200
            self._reply(
                state.patch_status,
                {
                    "code": state.patch_status,
                    "status": "ok" if ok else "bad request",
                    "response_id": "SUCCESS" if ok else "INVALID",
                },
            )

    return Handler


@pytest.fixture
def firewall(tmp_path: Path) -> Iterator[tuple[Firewall, int, str]]:
    state = Firewall()
    cert, key, pin = _certificate(tmp_path)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, server.server_address[1], pin
    finally:
        server.shutdown()
        server.server_close()


Approve = Callable[..., ea.VerifiedApproval]


@pytest.fixture
def approve(tmp_path: Path) -> Approve:
    private, public = generate_ed25519_keypair()
    signer, approvers = Ed25519Signer(private), {"owner": ea.Ed25519Verifier(public)}
    ledger = ea.ApprovalLedger(tmp_path / "ledger")

    def _approve(
        capability: str = "block_indicator", target: str = "203.0.113.7"
    ) -> ea.VerifiedApproval:
        token = ea.issue_approval(
            signer,
            approver="owner",
            capability=capability,
            target=target,
            plan_id=_PLAN,
            ttl_seconds=300,
        )
        return ea.authorize(
            token,
            capability=capability,
            target=target,
            plan_id=_PLAN,
            approvers=approvers,
            ledger=ledger,
        )

    return _approve


@pytest.fixture(autouse=True)
def _api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(live.PFSENSE_KEY_ENV, _KEY)


def _client(
    tmp_path: Path,
    port: int,
    pin: str,
    *,
    grants: tuple[str, ...] = _GRANTS,
    declared: bool = True,
    clock: Callable[[], float] | None = None,
) -> live.PfSenseLive:
    egress = EgressAllowlist(
        [LabHost(address=parse_address("127.0.0.1"), port=port, authorization="test stub")]
        if declared
        else []
    )
    kwargs: dict[str, Any] = {} if clock is None else {"clock": clock}
    return live.PfSenseLive(
        live.FirewallTarget(address="127.0.0.1", port=port, certificate_sha256=pin),
        PfSenseConfig(protected=frozenset({"192.0.2.1"})),
        engine=PolicyEngine(allow=grants),
        egress=egress,
        audit=AuditLogger(tmp_path / "audit.log"),
        **kwargs,
    )


def _decisions(tmp_path: Path) -> list[str]:
    text = (tmp_path / "audit.log").read_text()
    return [json.loads(line)["decision"] for line in text.splitlines() if line.strip()]


@pytest.mark.security
def test_an_approved_block_is_sent_exactly_as_signed(
    tmp_path: Path, firewall: tuple[Firewall, int, str], approve: Approve
) -> None:
    state, port, pin = firewall
    result = _client(tmp_path, port, pin).send(approve())
    assert [r["method"] for r in state.seen] == ["GET", "PATCH"]
    assert state.seen[0]["path"] == "/api/v2/firewall/aliases?name=IANUA_BLOCK"
    assert state.seen[1]["body"] == {
        "id": 3,
        "address": ["203.0.113.7"],
        "append": True,
        "apply": True,
    }
    assert all(r["key"] == _KEY for r in state.seen)
    assert result["status"] == 200 and result["alias"] == "IANUA_BLOCK"
    assert "sent" in _decisions(tmp_path)
    assert AuditLogger(tmp_path / "audit.log").verify()


@pytest.mark.security
def test_restore_removes_from_the_isolate_alias(
    tmp_path: Path, firewall: tuple[Firewall, int, str], approve: Approve
) -> None:
    state, port, pin = firewall
    _client(tmp_path, port, pin).send(approve("restore_host"))
    assert state.seen[1]["body"] == {
        "id": 4,
        "address": ["203.0.113.7"],
        "remove": True,
        "apply": True,
    }


@pytest.mark.security
def test_a_wrong_certificate_sends_nothing(
    tmp_path: Path, firewall: tuple[Firewall, int, str], approve: Approve
) -> None:
    state, port, _ = firewall
    with pytest.raises(live.PinMismatchError, match="nothing was sent"):
        _client(tmp_path, port, "0" * 64).send(approve())
    assert state.seen == [], "the request was written before the pin was checked"


@pytest.mark.security
@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"grants": ()}, "not granted"),
        ({"grants": (live.PROBE_LABEL,)}, "not granted"),
        ({"declared": False}, "not a declared lab host"),
    ],
)
def test_no_grant_or_no_declaration_sends_nothing(
    tmp_path: Path,
    firewall: tuple[Firewall, int, str],
    approve: Approve,
    kwargs: dict[str, Any],
    match: str,
) -> None:
    state, port, pin = firewall
    with pytest.raises(live.LiveError, match=match):
        _client(tmp_path, port, pin, **kwargs).send(approve())
    assert state.seen == []


@pytest.mark.security
@pytest.mark.parametrize(
    "value", ["", "short", "has space in it here ok", "k" * 20 + "\r\nX-Evil: 1"]
)
def test_a_missing_or_malformed_key_sends_nothing_and_is_never_echoed(
    tmp_path: Path,
    firewall: tuple[Firewall, int, str],
    approve: Approve,
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    state, port, pin = firewall
    monkeypatch.setenv(live.PFSENSE_KEY_ENV, value)
    with pytest.raises(live.LiveError, match=live.PFSENSE_KEY_ENV) as caught:
        _client(tmp_path, port, pin).send(approve())
    assert state.seen == []
    if value:
        assert value not in str(caught.value)
        assert value not in (tmp_path / "audit.log").read_text()


@pytest.mark.security
def test_the_key_never_reaches_the_audit_log(
    tmp_path: Path, firewall: tuple[Firewall, int, str], approve: Approve
) -> None:
    _, port, pin = firewall
    _client(tmp_path, port, pin).send(approve())
    assert _KEY not in (tmp_path / "audit.log").read_text()


@pytest.mark.security
@pytest.mark.parametrize(
    "aliases",
    [
        [],
        [
            {"id": 3, "name": "IANUA_BLOCK", "type": "host"},
            {"id": 9, "name": "IANUA_BLOCK", "type": "host"},
        ],
        [{"id": 3, "name": "IANUA_BLOCK", "type": "network"}],
        [{"id": True, "name": "IANUA_BLOCK", "type": "host"}],
        [{"id": "3", "name": "IANUA_BLOCK", "type": "host"}],
        [{"id": -1, "name": "IANUA_BLOCK", "type": "host"}],
    ],
)
def test_an_ambiguous_or_wrong_alias_changes_nothing(
    tmp_path: Path,
    firewall: tuple[Firewall, int, str],
    approve: Approve,
    aliases: list[dict[str, Any]],
) -> None:
    state, port, pin = firewall
    state.aliases = aliases
    with pytest.raises(live.LiveError, match="alias"):
        _client(tmp_path, port, pin).send(approve())
    assert [r["method"] for r in state.seen] == ["GET"], "a PATCH followed a failed precondition"


@pytest.mark.security
def test_a_lookup_answer_for_another_alias_name_is_refused(
    tmp_path: Path, firewall: tuple[Firewall, int, str], approve: Approve
) -> None:
    """A firewall that ignored the ``name`` filter would answer with some other alias."""
    state, port, pin = firewall
    state.aliases = [{"id": 3, "name": "SOMETHING_ELSE", "type": "host"}]
    state.ignore_filter = True
    with pytest.raises(live.LiveError, match="named exactly IANUA_BLOCK"):
        _client(tmp_path, port, pin).send(approve())
    assert [r["method"] for r in state.seen] == ["GET"]


@pytest.mark.security
def test_a_refusal_by_the_firewall_is_recorded_and_raised(
    tmp_path: Path, firewall: tuple[Firewall, int, str], approve: Approve
) -> None:
    state, port, pin = firewall
    state.patch_status = 400
    with pytest.raises(live.LiveError, match="refused the change"):
        _client(tmp_path, port, pin).send(approve())
    assert "refused-by-firewall" in _decisions(tmp_path)


@pytest.mark.security
def test_a_lost_answer_after_sending_is_reported_as_unknown(
    tmp_path: Path, firewall: tuple[Firewall, int, str], approve: Approve
) -> None:
    state, port, pin = firewall
    state.drop_patch = True
    with pytest.raises(live.OutcomeUnknownError, match="check alias IANUA_BLOCK"):
        _client(tmp_path, port, pin).send(approve())
    assert [r["method"] for r in state.seen] == ["GET", "PATCH"]
    assert "unknown" in _decisions(tmp_path)


@pytest.mark.security
def test_an_oversized_response_is_refused_before_parsing(
    tmp_path: Path, firewall: tuple[Firewall, int, str], approve: Approve
) -> None:
    state, port, pin = firewall
    state.oversized = True
    with pytest.raises(live.LiveError, match="exceeds"):
        _client(tmp_path, port, pin).send(approve())
    assert [r["method"] for r in state.seen] == ["GET"]


@pytest.mark.security
def test_an_approval_sends_once_and_only_while_fresh(
    tmp_path: Path, firewall: tuple[Firewall, int, str], approve: Approve
) -> None:
    state, port, pin = firewall
    client = _client(tmp_path, port, pin)
    approval = approve()
    client.send(approval)
    with pytest.raises(live.LiveError, match="already been used"):
        client.send(approval)
    assert len(state.seen) == 2
    stale = approve()
    with pytest.raises(live.LiveError, match="expired"):
        _client(tmp_path, port, pin, clock=lambda: stale.expires_at).send(stale)
    assert len(state.seen) == 2


@pytest.mark.security
def test_a_configured_proxy_is_not_used(
    tmp_path: Path,
    firewall: tuple[Firewall, int, str],
    approve: Approve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proxy would sit between IANUA and the firewall; the client connects directly."""
    _, port, pin = firewall
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://203.0.113.250:9")
    assert _client(tmp_path, port, pin).send(approve())["status"] == 200


@pytest.mark.security
def test_probe_is_a_separate_read_only_grant(
    tmp_path: Path, firewall: tuple[Firewall, int, str]
) -> None:
    state, port, pin = firewall
    with pytest.raises(live.LiveError, match="not granted"):
        _client(tmp_path, port, pin, grants=(live.SEND_LABEL,)).probe()
    found = _client(tmp_path, port, pin, grants=(live.PROBE_LABEL,)).probe()
    assert found == {"IANUA_BLOCK": 3, "IANUA_ISOLATE": 4}
    assert {r["method"] for r in state.seen} == {"GET"}


@pytest.mark.security
def test_local_config_loads_and_always_protects_the_firewall(tmp_path: Path) -> None:
    path = tmp_path / "pfsense.local.json"
    pin = "a" * 64
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "address": "192.0.2.1",
                "port": 443,
                "certificate_sha256": pin,
                "protected": ["198.51.100.2"],
            }
        )
    )
    target, config = live.load_local_config(path)
    assert (target.address, target.port, target.certificate_sha256) == ("192.0.2.1", 443, pin)
    assert config.protected == frozenset({"192.0.2.1", "198.51.100.2"})


@pytest.mark.security
@pytest.mark.parametrize(
    "document",
    [
        {
            "version": 1,
            "address": "192.0.2.1",
            "port": 443,
            "certificate_sha256": "A" * 64,
            "protected": [],
        },
        {
            "version": 1,
            "address": "192.0.2.1",
            "port": 443,
            "certificate_sha256": "a" * 63,
            "protected": [],
        },
        {
            "version": 1,
            "address": "fw.lab",
            "port": 443,
            "certificate_sha256": "a" * 64,
            "protected": [],
        },
        {
            "version": 1,
            "address": "2001:DB8::1",
            "port": 443,
            "certificate_sha256": "a" * 64,
            "protected": [],
        },
        {
            "version": 1,
            "address": "192.0.2.1",
            "port": True,
            "certificate_sha256": "a" * 64,
            "protected": [],
        },
        {
            "version": 1,
            "address": "192.0.2.1",
            "port": 443,
            "certificate_sha256": "a" * 64,
            "protected": [],
            "url": "x",
        },
        {
            "version": 2,
            "address": "192.0.2.1",
            "port": 443,
            "certificate_sha256": "a" * 64,
            "protected": [],
        },
        {"version": 1, "address": "192.0.2.1", "port": 443, "certificate_sha256": "a" * 64},
    ],
)
def test_a_malformed_local_config_raises(tmp_path: Path, document: dict[str, Any]) -> None:
    path = tmp_path / "pfsense.local.json"
    path.write_text(json.dumps(document))
    with pytest.raises(live.LiveError):
        live.load_local_config(path)


@pytest.mark.security
def test_a_missing_local_config_raises(tmp_path: Path) -> None:
    with pytest.raises(live.LiveError, match="cannot read"):
        live.load_local_config(tmp_path / "absent.json")


@pytest.mark.security
def test_the_shipped_policy_does_not_grant_sending() -> None:
    """The committed bundle must not ship either label; granting is the operator's reviewed edit."""
    from agents.policies.bundle import load_bundle

    engine = load_bundle()
    for label in _GRANTS:
        assert engine.decide(action_class="external_network", label=label).decision != "allow"


@pytest.mark.security
def test_local_declarations_are_gitignored() -> None:
    repo = Path(__file__).resolve().parents[2]
    import subprocess

    for path in (live.DEFAULT_LOCAL_CONFIG, live.DEFAULT_LOCAL_EGRESS):
        result = subprocess.run(  # noqa: S603 - fixed argv
            ["git", "check-ignore", "-q", str(path.relative_to(repo))],  # noqa: S607
            cwd=repo,
            check=False,
        )
        assert result.returncode == 0, (
            f"{path.name} would be committed — it holds internal addresses"
        )


# --- the CLI, end to end, as a subprocess -------------------------------------------

_CLI = Path(__file__).resolve().parents[2] / "scripts" / "pfsense_containment.py"


def _cli_files(
    tmp_path: Path, port: int, pin: str, *, grants: list[str]
) -> tuple[dict[str, str], str]:
    """Write every local file the CLI reads; return (env, approver private key hex)."""
    private, public = generate_ed25519_keypair()
    (tmp_path / "pfsense.local.json").write_text(
        json.dumps(
            {
                "version": 1,
                "address": "127.0.0.1",
                "port": port,
                "certificate_sha256": pin,
                "protected": [],
            }
        )
    )
    (tmp_path / "egress.local.json").write_text(
        json.dumps(
            {
                "version": 1,
                "hosts": [{"address": "127.0.0.1", "port": port, "authorization": "test stub"}],
            }
        )
    )
    policy = json.loads(
        (Path(__file__).resolve().parents[2] / "agents/policies/policy.json").read_text()
    )
    policy["allow"] = grants
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    (tmp_path / "approvers.json").write_text(
        json.dumps(
            {
                "version": 1,
                "approvers": [{"id": "owner", "public_key": public.hex(), "authorization": "test"}],
            }
        )
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("IANUA_")}
    env[live.PFSENSE_KEY_ENV] = _KEY
    return env, private.hex()


def _run_cli(args: list[str], env: dict[str, str], stdin: str = "") -> tuple[int, str, str]:
    import subprocess
    import sys

    result = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter and script
        [sys.executable, str(_CLI), *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    return result.returncode, result.stdout, result.stderr


def _local_args(tmp_path: Path) -> list[str]:
    return [
        "--config", str(tmp_path / "pfsense.local.json"),
        "--egress", str(tmp_path / "egress.local.json"),
        "--policy", str(tmp_path / "policy.json"),
        "--audit", str(tmp_path / "cli-audit.log"),
    ]  # fmt: skip


@pytest.mark.security
def test_cli_issue_then_send_applies_the_change(
    tmp_path: Path, firewall: tuple[Firewall, int, str]
) -> None:
    state, port, pin = firewall
    env, private = _cli_files(tmp_path, port, pin, grants=[live.SEND_LABEL])
    action = ["--capability", "block_indicator", "--target", "203.0.113.7", "--plan", _PLAN]
    code, token, err = _run_cli(
        ["issue", *action, "--approver", "owner"], {**env, "IANUA_APPROVER_KEY": private}
    )
    assert code == 0, err
    send = [
        "send", *_local_args(tmp_path), *action,
        "--approvers", str(tmp_path / "approvers.json"), "--ledger", str(tmp_path / "ledger"),
    ]  # fmt: skip
    code, out, err = _run_cli(send, env, stdin=token)
    assert code == 0, err
    assert json.loads(out)["alias"] == "IANUA_BLOCK"
    assert [r["method"] for r in state.seen] == ["GET", "PATCH"]
    code, _, err = _run_cli(send, env, stdin=token)
    assert code == 1 and "already been used" in err, "a replayed token must not send twice"
    assert len(state.seen) == 2
    assert private not in (tmp_path / "cli-audit.log").read_text()


@pytest.mark.security
def test_cli_without_the_grant_exits_3_and_sends_nothing(
    tmp_path: Path, firewall: tuple[Firewall, int, str]
) -> None:
    state, port, pin = firewall
    env, _ = _cli_files(tmp_path, port, pin, grants=[])
    code, _, err = _run_cli(["probe", *_local_args(tmp_path)], env)
    assert code == 3 and "not granted" in err
    assert state.seen == []


@pytest.mark.security
def test_cli_issue_without_a_key_refuses_and_prints_no_token(tmp_path: Path) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("IANUA_")}
    code, out, err = _run_cli(
        [
            "issue",
            "--capability",
            "block_indicator",
            "--target",
            "203.0.113.7",
            "--plan",
            _PLAN,
            "--approver",
            "owner",
        ],
        env,
    )
    assert code == 1 and out == "" and "IANUA_APPROVER_KEY" in err


@pytest.mark.security
def test_only_the_operator_cli_imports_the_live_client() -> None:
    """Nothing automatic may send: no scheduler, pipeline, agent or dashboard reaches the transport."""
    import ast

    repo = Path(__file__).resolve().parents[2]
    packages = ("agents", "attack", "intel", "ingest", "store", "correlation", "pipeline",
                "collect", "scripts", "mcp", "sli", "rag", "dashboard", "compliance")  # fmt: skip
    allowed = {
        repo / "scripts" / "pfsense_containment.py",
        repo / "agents" / "tools" / "pfsense_live.py",
    }
    importers = set()
    for package in packages:
        for path in (repo / package).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
                elif isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                if any(n == "agents.tools.pfsense_live" for n in names):
                    importers.add(path)
    assert importers, "found no importer at all — the guard would be vacuous"
    assert importers <= allowed, sorted(str(p.relative_to(repo)) for p in importers - allowed)
