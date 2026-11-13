# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the pfSense dry-run adapter (stage 8, phase 2).

Every approval here is obtained through the real
:func:`agents.policies.execution_approval.authorize`, with keys generated per
test, so the adapter is exercised on exactly what phase 3 will hand it.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from agents.policies import execution_approval as ea
from agents.policies.audit import AuditLogger
from agents.policies.signing import Ed25519Signer, generate_ed25519_keypair
from agents.tools import pfsense as pf

_PLAN = "plan-0123456789abcdef"
_NOW = 1_800_000_000
_REPO = Path(__file__).resolve().parents[2]
_MODULE = Path(pf.__file__)

Approve = Callable[..., ea.VerifiedApproval]


@pytest.fixture
def approve(tmp_path: Path) -> Approve:
    """Return a function that signs and authorizes one approval end to end."""
    private, public = generate_ed25519_keypair()
    signer = Ed25519Signer(private)
    approvers = {"owner": ea.Ed25519Verifier(public)}
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
            now=_NOW,
        )
        return ea.authorize(
            token,
            capability=capability,
            target=target,
            plan_id=_PLAN,
            approvers=approvers,
            ledger=ledger,
            now=_NOW + 1,
        )

    return _approve


def _adapter(**kwargs: object) -> pf.PfSenseDryRun:
    return pf.PfSenseDryRun(clock=lambda: _NOW + 2, **kwargs)  # type: ignore[arg-type]


@pytest.mark.security
@pytest.mark.parametrize(
    ("capability", "alias", "operation"),
    [
        ("block_indicator", pf.DEFAULT_BLOCK_ALIAS, "append"),
        ("unblock_indicator", pf.DEFAULT_BLOCK_ALIAS, "remove"),
        ("isolate_host", pf.DEFAULT_ISOLATE_ALIAS, "append"),
        ("restore_host", pf.DEFAULT_ISOLATE_ALIAS, "remove"),
    ],
)
def test_each_capability_maps_to_one_alias_edit(
    approve: Approve, capability: str, alias: str, operation: str
) -> None:
    change = _adapter().dry_run(approve(capability))
    assert change.lookup.as_dict() == {
        "method": "GET",
        "path": "/api/v2/firewall/aliases",
        "query": [("name", alias)],
        "body": None,
    }
    assert change.change.method == "PATCH" and change.change.path == "/api/v2/firewall/alias"
    assert change.change.body == {
        "id": None,
        "address": ["203.0.113.7"],
        operation: True,
        "apply": True,
    }
    assert "exactly one alias" in change.precondition and alias in change.precondition


@pytest.mark.security
def test_the_request_names_only_what_was_signed(approve: Approve) -> None:
    """There is no target parameter to diverge from the approval: the change is derived from it."""
    approval = approve(target="198.51.100.4")
    change = _adapter().dry_run(approval)
    rendered = json.dumps(change.as_dict())
    assert change.target == approval.target == "198.51.100.4"
    assert "203.0.113.7" not in rendered
    assert change.approval_digest == approval.digest


@pytest.mark.security
@pytest.mark.parametrize("capability", ["disable_account", "enable_account"])
def test_non_firewall_capabilities_fail_closed(approve: Approve, capability: str) -> None:
    with pytest.raises(pf.PfSenseError, match="not a pfSense action"):
        _adapter().dry_run(approve(capability, target="jdoe"))


@pytest.mark.security
@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("lab-gw.corp", "IP literal"),
        ("203.0.113.0/24", "IP literal"),
        ("0.0.0.0", "IP literal"),  # noqa: S104 - refused by the control under test, not a bind address
        ("169.254.169.254", "IP literal"),
        ("224.0.0.1", "IP literal"),
        ("::ffff:203.0.113.7", "IP literal"),
        ("fe80::1%2", "IP literal"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("2001:DB8::1", "canonical"),
        ("2001:db8:0::1", "canonical"),
    ],
)
def test_targets_must_be_one_canonical_routable_address(
    approve: Approve, target: str, reason: str
) -> None:
    with pytest.raises(pf.PfSenseError, match=reason):
        _adapter().dry_run(approve(target=target))


@pytest.mark.security
def test_ipv6_canonical_target_is_accepted(approve: Approve) -> None:
    change = _adapter().dry_run(approve(target="2001:db8::1"))
    assert change.change.body is not None and change.change.body["address"] == ["2001:db8::1"]


@pytest.mark.security
def test_protected_addresses_cannot_be_blocked_but_can_be_recovered(approve: Approve) -> None:
    adapter = _adapter(config=pf.PfSenseConfig(protected=frozenset({"192.0.2.1"})))
    for capability in ("block_indicator", "isolate_host"):
        with pytest.raises(pf.PfSenseError, match="protected"):
            adapter.dry_run(approve(capability, target="192.0.2.1"))
    for capability in ("unblock_indicator", "restore_host"):
        assert adapter.dry_run(approve(capability, target="192.0.2.1")).operation == "remove"


@pytest.mark.security
def test_an_approval_is_used_once_and_only_while_fresh(approve: Approve) -> None:
    adapter = _adapter()
    approval = approve()
    adapter.dry_run(approval)
    with pytest.raises(pf.PfSenseError, match="already been used"):
        adapter.dry_run(approval)
    late = pf.PfSenseDryRun(clock=lambda: approval.expires_at)
    with pytest.raises(pf.PfSenseError, match="expired"):
        late.dry_run(approve())


@pytest.mark.security
def test_a_forged_or_subclassed_approval_is_refused(approve: Approve, tmp_path: Path) -> None:
    """Only the exact type authorize() returns is accepted — not a look-alike."""
    real = approve()

    @dataclass(frozen=True)
    class LookAlike:
        approver: str = "owner|forged"
        capability: str = "block_indicator"
        target: str = "203.0.113.7"
        plan_id: str = _PLAN
        expires_at: int = _NOW + 300
        digest: str = real.digest

    class Sub(ea.VerifiedApproval):
        __slots__ = ()

    sub = Sub(
        real.approver, real.capability, real.target, real.plan_id, real.expires_at, real.digest
    )
    audit = AuditLogger(tmp_path / "audit.log")
    adapter = _adapter(audit=audit)
    for forged in (LookAlike(), sub):
        with pytest.raises(pf.PfSenseError, match="VerifiedApproval"):
            adapter.dry_run(forged)  # type: ignore[arg-type]
    lines = [json.loads(line) for line in audit.path.read_text().splitlines() if line.strip()]
    assert [line["actor"] for line in lines] == ["pfsense", "pfsense"], (
        "a forged identity must not reach the actor field"
    )
    assert audit.verify()


@pytest.mark.security
def test_both_outcomes_are_audited_and_bind_approval_to_change(
    approve: Approve, tmp_path: Path
) -> None:
    audit = AuditLogger(tmp_path / "audit.log")
    adapter = _adapter(audit=audit)
    change = adapter.dry_run(approve())
    with pytest.raises(pf.PfSenseError):
        adapter.dry_run(approve(target="127.0.0.1"))
    lines = [json.loads(line) for line in audit.path.read_text().splitlines() if line.strip()]
    assert [line["decision"] for line in lines] == ["dry-run", "deny"]
    assert lines[0]["actor"] == "pfsense/owner"
    assert change.approval_digest in lines[0]["reason"] and change.digest in lines[0]["reason"]
    assert "not sent" in lines[0]["reason"]
    assert audit.verify()


@pytest.mark.security
def test_prepare_is_deterministic_and_the_digest_covers_the_target(approve: Approve) -> None:
    adapter = _adapter()
    first = approve()
    assert adapter.prepare(first).digest == adapter.prepare(first).digest
    assert adapter.prepare(first).digest != adapter.prepare(approve(target="203.0.113.8")).digest


@pytest.mark.security
@pytest.mark.parametrize(
    "kwargs",
    [
        {"block_alias": "1BAD"},
        {"block_alias": "has space"},
        {"isolate_alias": "x" * 32},
        {"block_alias": "SAME", "isolate_alias": "SAME"},
        {"protected": frozenset({"lab-gw.corp"})},
        {"protected": {"192.0.2.1"}},
    ],
)
def test_config_is_validated_on_construction(kwargs: dict[str, object]) -> None:
    with pytest.raises(pf.PfSenseError):
        pf.PfSenseConfig(**kwargs)  # type: ignore[arg-type]


@pytest.mark.security
def test_the_adapter_has_no_route_to_a_network() -> None:
    """Phase 2 is dry-run by construction: no transport module, no file or process access."""
    banned = {
        "socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx", "aiohttp",
        "asyncio", "subprocess", "ftplib", "smtplib", "telnetlib", "paramiko", "os", "shutil",
    }  # fmt: skip
    tree = ast.parse(_MODULE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {alias.name.split(".")[0] for alias in node.names} & banned
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in banned, node.module
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"open", "eval", "exec", "__import__"}, node.func.id


@pytest.mark.security
def test_only_authorize_constructs_a_verified_approval() -> None:
    """A VerifiedApproval built anywhere else in shipped code would bypass the signature."""
    packages = ("agents", "attack", "intel", "ingest", "store", "correlation", "pipeline",
                "collect", "scripts", "mcp", "sli", "rag", "dashboard", "compliance")  # fmt: skip
    allowed = _REPO / "agents" / "policies" / "execution_approval.py"
    scanned = 0
    for package in packages:
        for path in sorted((_REPO / package).rglob("*.py")):
            scanned += 1
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else getattr(node.func, "attr", "")
                )
                if name == "VerifiedApproval":
                    assert path == allowed, (
                        f"{path.relative_to(_REPO)} constructs a VerifiedApproval"
                    )
    assert scanned > 100, "scanned too few modules — the guard would be vacuous"


@pytest.mark.security
def test_supported_set_is_a_subset_of_what_can_be_approved() -> None:
    assert pf.SUPPORTED <= ea.CAPABILITIES
    assert {"disable_account", "enable_account"} == ea.CAPABILITIES - pf.SUPPORTED
