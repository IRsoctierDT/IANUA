# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the signed per-action execution approval (stage 8, phase 1).

Each test names the attack it refuses. Keys are generated per test and never
written anywhere but ``tmp_path``.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agents.policies import execution_approval as ea
from agents.policies.audit import AuditLogger
from agents.policies.signing import Ed25519Signer, HmacSigner, generate_ed25519_keypair

Keys = tuple[Ed25519Signer, dict[str, ea.Ed25519Verifier]]
Mutation = Callable[[dict[str, Any]], object]

_PLAN = "plan-0123456789abcdef"
_NOW = 1_800_000_000
_MODULE = Path(ea.__file__)
_CONTAINMENT = _MODULE.parents[1] / "tools" / "containment.py"


@pytest.fixture
def keys() -> Keys:
    private, public = generate_ed25519_keypair()
    return Ed25519Signer(private), {"owner": ea.Ed25519Verifier(public)}


@pytest.fixture
def ledger(tmp_path: Path) -> ea.ApprovalLedger:
    return ea.ApprovalLedger(tmp_path / "state" / "approvals.ledger")


def _issue(signer: Ed25519Signer, **overrides: object) -> str:
    kwargs: dict[str, object] = {
        "approver": "owner",
        "capability": "block_indicator",
        "target": "203.0.113.7",
        "plan_id": _PLAN,
        "ttl_seconds": 300,
        "now": _NOW,
    }
    kwargs.update(overrides)
    return ea.issue_approval(signer, **kwargs)  # type: ignore[arg-type]


def _authorize(
    token: str, approvers: dict[str, ea.Ed25519Verifier], ledger: ea.ApprovalLedger, **kw: object
) -> ea.VerifiedApproval:
    args: dict[str, object] = {
        "capability": "block_indicator",
        "target": "203.0.113.7",
        "plan_id": _PLAN,
        "approvers": approvers,
        "ledger": ledger,
        "now": _NOW + 10,
    }
    args.update(kw)
    return ea.authorize(token, **args)  # type: ignore[arg-type]


def _resign(signer: Ed25519Signer, token: str, **changes: object) -> str:
    envelope = json.loads(token)
    envelope["approval"].update(changes)
    envelope["signature"] = signer.sign(ea._canonical(envelope["approval"]))
    return json.dumps(envelope)


@pytest.mark.security
def test_a_valid_approval_is_accepted_once(keys: Keys, ledger: ea.ApprovalLedger) -> None:
    signer, approvers = keys
    token = _issue(signer)
    verified = _authorize(token, approvers, ledger)
    assert (verified.approver, verified.capability, verified.target) == (
        "owner",
        "block_indicator",
        "203.0.113.7",
    )
    assert len(verified.digest) == 64
    with pytest.raises(ea.ApprovalError, match="already been used"):
        _authorize(token, approvers, ledger)


@pytest.mark.security
def test_replay_is_refused_across_ledger_instances(keys: Keys, ledger: ea.ApprovalLedger) -> None:
    """Single use is a property of the file, not of one process's memory."""
    signer, approvers = keys
    token = _issue(signer)
    _authorize(token, approvers, ledger)
    with pytest.raises(ea.ApprovalError, match="already been used"):
        _authorize(token, approvers, ea.ApprovalLedger(ledger.path))


@pytest.mark.security
def test_two_approvals_for_the_same_action_are_distinct(
    keys: Keys, ledger: ea.ApprovalLedger
) -> None:
    signer, approvers = keys
    first, second = _issue(signer), _issue(signer)
    assert first != second
    assert (
        _authorize(first, approvers, ledger).digest != _authorize(second, approvers, ledger).digest
    )


@pytest.mark.security
@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("capability", "isolate_host"),
        ("target", "203.0.113.8"),
        ("plan_id", "plan-ffffffffffffffff"),
    ],
)
def test_an_approval_for_one_action_cannot_authorize_another(
    keys: Keys, ledger: ea.ApprovalLedger, name: str, value: object
) -> None:
    signer, approvers = keys
    with pytest.raises(ea.ApprovalError, match=f"different {name}"):
        _authorize(_issue(signer), approvers, ledger, **{name: value})
    assert not ledger.path.exists() or ledger.path.read_text() == "", (
        "a refused approval must not be spent"
    )


@pytest.mark.security
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target", "203.0.113.8"),
        ("capability", "isolate_host"),
        ("expires_at", _NOW + 900),
        ("approver", "mallory"),
    ],
)
def test_editing_any_signed_field_breaks_the_signature(
    keys: Keys, ledger: ea.ApprovalLedger, field: str, value: object
) -> None:
    signer, approvers = keys
    envelope = json.loads(_issue(signer))
    envelope["approval"][field] = value
    approvers = {**approvers, "mallory": approvers["owner"]}
    with pytest.raises(ea.ApprovalError, match="does not verify"):
        _authorize(json.dumps(envelope), approvers, ledger)


@pytest.mark.security
def test_a_key_not_registered_for_that_approver_is_refused(
    keys: Keys, ledger: ea.ApprovalLedger
) -> None:
    """Key substitution: a valid signature by the wrong key under a real id."""
    _, approvers = keys
    other_private, _ = generate_ed25519_keypair()
    with pytest.raises(ea.ApprovalError, match="does not verify"):
        _authorize(_issue(Ed25519Signer(other_private)), approvers, ledger)


@pytest.mark.security
def test_an_unregistered_approver_is_refused(keys: Keys, ledger: ea.ApprovalLedger) -> None:
    signer, approvers = keys
    with pytest.raises(ea.ApprovalError, match="not registered"):
        _authorize(_issue(signer, approver="someone"), approvers, ledger)


@pytest.mark.security
def test_hmac_is_refused_at_issue_and_at_verify(keys: Keys, ledger: ea.ApprovalLedger) -> None:
    """A symmetric verifier could forge, so the downgrade is closed both ways."""
    signer, approvers = keys
    with pytest.raises(ea.ApprovalError, match="Ed25519 only"):
        ea.issue_approval(
            HmacSigner(b"k" * 32),  # type: ignore[arg-type]
            approver="owner",
            capability="block_indicator",
            target="x",
            plan_id=_PLAN,
            ttl_seconds=60,
            now=_NOW,
        )
    envelope = json.loads(_issue(signer))
    envelope["algo"] = "hmac-sha256"
    with pytest.raises(ea.ApprovalError, match="Ed25519 only"):
        _authorize(json.dumps(envelope), approvers, ledger)


@pytest.mark.security
def test_signature_is_domain_separated(keys: Keys, ledger: ea.ApprovalLedger) -> None:
    """A signature over the bare JSON (another message this repo might sign) is not an approval."""
    signer, approvers = keys
    envelope = json.loads(_issue(signer))
    # Built independently of ``_canonical``: deriving it by slicing that
    # function's output made this test pass against a version with no domain.
    body = json.dumps(
        envelope["approval"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    assert ea._canonical(envelope["approval"]) == ea.DOMAIN + body
    envelope["signature"] = signer.sign(body)
    with pytest.raises(ea.ApprovalError, match="does not verify"):
        _authorize(json.dumps(envelope), approvers, ledger)


@pytest.mark.security
def test_time_is_bounded_on_both_sides(keys: Keys, ledger: ea.ApprovalLedger) -> None:
    signer, approvers = keys
    with pytest.raises(ea.ApprovalError, match="expired"):
        _authorize(_issue(signer, ttl_seconds=60), approvers, ledger, now=_NOW + 60)
    with pytest.raises(ea.ApprovalError, match="future"):
        _authorize(_issue(signer), approvers, ledger, now=_NOW - ea.CLOCK_SKEW_SECONDS - 1)
    for ttl in (0, -5, ea.MAX_TTL_SECONDS + 1):
        with pytest.raises(ea.ApprovalError, match="lifetime"):
            _issue(signer, ttl_seconds=ttl)


@pytest.mark.security
def test_an_over_long_lifetime_is_refused_even_when_validly_signed(
    keys: Keys, ledger: ea.ApprovalLedger
) -> None:
    """The bound is enforced at verify, not trusted from the issuer."""
    signer, approvers = keys
    token = _resign(signer, _issue(signer), expires_at=_NOW + 86_400)
    with pytest.raises(ea.ApprovalError, match="lifetime"):
        _authorize(token, approvers, ledger)


@pytest.mark.security
@pytest.mark.parametrize(
    "capability", ["stop_process", "quarantine_file", "delete", "isolate_host "]
)
def test_only_listed_capabilities_are_approvable(
    keys: Keys, ledger: ea.ApprovalLedger, capability: str
) -> None:
    signer, approvers = keys
    with pytest.raises(ea.ApprovalError, match="not approvable"):
        _issue(signer, capability=capability)
    token = _resign(signer, _issue(signer), capability=capability)
    with pytest.raises(ea.ApprovalError, match="not approvable"):
        _authorize(token, approvers, ledger, capability=capability)


@pytest.mark.security
@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e["approval"].update(issued_at=True),
        lambda e: e["approval"].update(issued_at=float(_NOW)),
        lambda e: e["approval"].update(version=2),
        lambda e: e["approval"].update(extra="x"),
        lambda e: e["approval"].pop("nonce"),
        lambda e: e["approval"].update(target="a|b"),
        lambda e: e["approval"].update(target="has space"),
        lambda e: e["approval"].update(target="*"[:0]),
        lambda e: e["approval"].update(plan_id="plan-XYZ"),
        lambda e: e.update(extra=1),
        lambda e: e.update(signature="zz"),
    ],
)
def test_malformed_tokens_are_rejected_not_repaired(
    keys: Keys, ledger: ea.ApprovalLedger, mutate: Mutation
) -> None:
    signer, approvers = keys
    envelope = json.loads(_issue(signer))
    mutate(envelope)
    with pytest.raises(ea.ApprovalError):
        _authorize(json.dumps(envelope), approvers, ledger)


@pytest.mark.security
def test_duplicate_keys_and_oversized_tokens_are_refused(
    keys: Keys, ledger: ea.ApprovalLedger
) -> None:
    signer, approvers = keys
    token = _issue(signer)
    duplicated = token[:-1] + ',"algo":"ed25519"}'
    with pytest.raises(ea.ApprovalError, match="repeats"):
        _authorize(duplicated, approvers, ledger)
    with pytest.raises(ea.ApprovalError, match="oversized"):
        _authorize(" " * (ea.MAX_TOKEN_BYTES + 1), approvers, ledger)
    with pytest.raises(ea.ApprovalError, match="missing"):
        _authorize("", approvers, ledger)


@pytest.mark.security
def test_ledger_refuses_a_symlink_and_a_readable_file(keys: Keys, tmp_path: Path) -> None:
    signer, approvers = keys
    real = tmp_path / "real"
    real.write_text("")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(ea.ApprovalError, match="cannot open"):
        _authorize(_issue(signer), approvers, ea.ApprovalLedger(link))
    loose = tmp_path / "loose"
    loose.write_text("")
    loose.chmod(0o644)
    with pytest.raises(ea.ApprovalError, match="readable by others"):
        _authorize(_issue(signer), approvers, ea.ApprovalLedger(loose))


@pytest.mark.security
def test_ledger_is_created_owner_only(keys: Keys, ledger: ea.ApprovalLedger) -> None:
    signer, approvers = keys
    _authorize(_issue(signer), approvers, ledger)
    assert ledger.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.security
def test_both_outcomes_are_audited_and_the_allow_names_the_digest(
    keys: Keys, ledger: ea.ApprovalLedger, tmp_path: Path
) -> None:
    signer, approvers = keys
    audit = AuditLogger(tmp_path / "audit.log")
    verified = _authorize(_issue(signer), approvers, ledger, audit=audit)
    with pytest.raises(ea.ApprovalError):
        _authorize(_issue(signer), approvers, ledger, audit=audit, target="a|b c")
    lines = [
        json.loads(line)
        for line in (tmp_path / "audit.log").read_text().splitlines()
        if line.strip()
    ]
    assert [line["decision"] for line in lines] == ["allow", "deny"]
    assert verified.digest in lines[0]["reason"] and lines[0]["actor"] == "approval/owner"
    assert "|" not in lines[1]["action"], (
        "a hostile target must not corrupt (or mask) the deny record"
    )
    assert audit.verify()


@pytest.mark.security
def test_the_shipped_registry_is_empty_so_the_default_is_deny(
    keys: Keys, ledger: ea.ApprovalLedger
) -> None:
    signer, _ = keys
    approvers = ea.load_approvers()
    assert approvers == {}
    with pytest.raises(ea.ApprovalError, match="not registered"):
        _authorize(_issue(signer), approvers, ledger)


@pytest.mark.security
@pytest.mark.parametrize(
    "document",
    [
        "not json",
        '{"version": 1}',
        '{"version": 1, "approvers": [{"id": "owner", "public_key": "00"}]}',
        '{"version": 1, "approvers": [{"id": "owner", "public_key": "'
        + "a" * 64
        + '", "authorization": " "}]}',
        '{"version": 1, "version": 1, "approvers": []}',
    ],
)
def test_a_broken_registry_raises_rather_than_meaning_nobody(tmp_path: Path, document: str) -> None:
    path = tmp_path / "approvers.json"
    path.write_text(document)
    with pytest.raises(ea.ApprovalError):
        ea.load_approvers(path)
    with pytest.raises(ea.ApprovalError, match="cannot load"):
        ea.load_approvers(tmp_path / "missing.json")


@pytest.mark.security
def test_a_registry_may_not_reuse_a_key_under_two_ids(tmp_path: Path) -> None:
    _, public = generate_ed25519_keypair()
    entry = {"public_key": public.hex(), "authorization": "owner, lab"}
    path = tmp_path / "approvers.json"
    path.write_text(
        json.dumps({"version": 1, "approvers": [{"id": "a", **entry}, {"id": "b", **entry}]})
    )
    with pytest.raises(ea.ApprovalError, match="duplicates"):
        ea.load_approvers(path)


@pytest.mark.security
def test_capabilities_are_exactly_what_the_toolkit_routes_to_an_executor() -> None:
    """The approvable set cannot drift wider than what an executor is ever asked to do."""
    tree = ast.parse(_CONTAINMENT.read_text(encoding="utf-8"))
    routed = {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_run_executor"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }
    assert routed, "found no executor routes — the guard would be vacuous"
    assert routed == ea.CAPABILITIES


@pytest.mark.security
def test_the_approval_module_executes_nothing() -> None:
    """Phase 1 is a gate, not a capability: no route to a process, host or network."""
    banned = {
        "subprocess",
        "socket",
        "http",
        "urllib",
        "ssl",
        "signal",
        "shutil",
        "asyncio",
        "multiprocessing",
        "ctypes",
    }
    tree = ast.parse(_MODULE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {a.name.split(".")[0] for a in node.names} & banned
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in banned
        elif isinstance(node, ast.FunctionDef):
            assert node.name not in {"execute", "perform", "run_action", "apply_plan", "arm"}


# --- ledger pruning -------------------------------------------------------------

_OLD = "a" * 64  # expired long before the grace window
_RECENT = "b" * 64  # expired, but inside the grace window
_LEGACY = "c" * 64  # a pre-pruning line with no recorded expiry


@pytest.mark.security
def test_each_consumption_records_its_expiry(keys: Keys, ledger: ea.ApprovalLedger) -> None:
    signer, approvers = keys
    verified = _authorize(_issue(signer), approvers, ledger)
    assert ledger.path.read_text() == f"{verified.digest} {verified.expires_at}\n"


@pytest.mark.security
def test_pruning_drops_only_entries_past_the_grace_window(
    keys: Keys, ledger: ea.ApprovalLedger, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, approvers = keys
    monkeypatch.setattr(ea, "PRUNE_THRESHOLD", 2)
    now = _NOW + 10
    ledger.path.parent.mkdir(parents=True)
    ledger.path.write_text(
        f"{_OLD} {now - ea.PRUNE_GRACE_SECONDS - 1}\n"
        f"{_RECENT} {now - ea.PRUNE_GRACE_SECONDS + 60}\n"
        f"{_LEGACY}\n"
    )
    ledger.path.chmod(0o600)
    fresh = _authorize(_issue(signer), approvers, ledger, now=now)
    kept = [line.split()[0] for line in ledger.path.read_text().splitlines()]
    assert kept == [_RECENT, _LEGACY, fresh.digest], "pruned the wrong entries"
    assert ledger.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.security
def test_nothing_is_rewritten_when_nothing_is_prunable(
    keys: Keys, ledger: ea.ApprovalLedger, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, approvers = keys
    monkeypatch.setattr(ea, "PRUNE_THRESHOLD", 0)
    _authorize(_issue(signer), approvers, ledger)
    inode = ledger.path.stat().st_ino
    _authorize(_issue(signer), approvers, ledger)
    assert ledger.path.stat().st_ino == inode


@pytest.mark.security
def test_a_live_approval_stays_spent_through_a_prune(
    keys: Keys, ledger: ea.ApprovalLedger, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer, approvers = keys
    monkeypatch.setattr(ea, "PRUNE_THRESHOLD", 0)
    ledger.path.parent.mkdir(parents=True)
    ledger.path.write_text(f"{_OLD} 1\n")
    ledger.path.chmod(0o600)
    token = _issue(signer)
    _authorize(token, approvers, ledger)
    assert _OLD not in ledger.path.read_text(), "the prune did not run"
    with pytest.raises(ea.ApprovalError, match="already been used"):
        _authorize(token, approvers, ledger)


@pytest.mark.security
@pytest.mark.parametrize(
    "content",
    ["not-a-digest\n", f"{_OLD} -5\n", f"{_OLD} 12 extra\n", f"{_OLD.upper()}\n", "\xff\n"],
)
def test_a_corrupt_ledger_refuses_rather_than_skipping(
    keys: Keys, ledger: ea.ApprovalLedger, content: str
) -> None:
    signer, approvers = keys
    ledger.path.parent.mkdir(parents=True)
    ledger.path.write_bytes(content.encode("latin-1"))
    ledger.path.chmod(0o600)
    with pytest.raises(ea.ApprovalError, match="corrupt"):
        _authorize(_issue(signer), approvers, ledger)


@pytest.mark.security
def test_the_lock_file_is_owner_only_and_never_a_symlink(keys: Keys, tmp_path: Path) -> None:
    signer, approvers = keys
    ledger = ea.ApprovalLedger(tmp_path / "ledger")
    _authorize(_issue(signer), approvers, ledger)
    assert ledger.lock_path.stat().st_mode & 0o777 == 0o600
    target = tmp_path / "elsewhere"
    target.write_text("")
    other = ea.ApprovalLedger(tmp_path / "second")
    other.lock_path.symlink_to(target)
    with pytest.raises(ea.ApprovalError, match="cannot open"):
        _authorize(_issue(signer), approvers, other)


@pytest.mark.security
def test_concurrent_consumers_spend_each_approval_exactly_once(
    keys: Keys, ledger: ea.ApprovalLedger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A realistic smoke test: two ledgers race on every token while every write prunes.

    It is **not** the guarantee. Mutation-checked, thread races under the GIL are
    too well-behaved: it caught a removed lock in one of three runs and a lock
    moved onto the ledger file itself in none.
    ``test_the_lock_survives_the_rewrite_it_guards`` is the deterministic test of
    the property; this one checks the whole path end to end.
    """
    import threading

    signer, approvers = keys
    monkeypatch.setattr(ea, "PRUNE_THRESHOLD", 0)
    ledger.path.parent.mkdir(parents=True)
    ledger.path.write_text("".join(f"{i:064x} 1\n" for i in range(50)))
    ledger.path.chmod(0o600)
    tokens = [_issue(signer) for _ in range(25)]
    wins: list[str] = []
    guard = threading.Lock()

    def race(token: str, barrier: threading.Barrier) -> None:
        mine = ea.ApprovalLedger(ledger.path)
        barrier.wait()
        try:
            _authorize(token, approvers, mine)
        except ea.ApprovalError:
            return
        with guard:
            wins.append(token)

    for token in tokens:
        barrier = threading.Barrier(2)
        threads = [threading.Thread(target=race, args=(token, barrier)) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert sorted(wins) == sorted(tokens), "a token was spent twice or not at all"


@pytest.mark.security
def test_the_lock_survives_the_rewrite_it_guards(tmp_path: Path) -> None:
    """While one ledger holds the lock and rewrites the file, another must still wait.

    Pruning replaces the ledger with a new file. A lock taken on the ledger's own
    descriptor would then sit on the unlinked old file, and a second consumer
    opening the path afresh would get the new file and lock it at once — two
    consumers inside the critical section, so one approval could be spent twice.
    Deterministic, unlike the race above: it fails against a ledger with no lock,
    and against one whose lock is the ledger file itself.
    """
    import threading

    path = tmp_path / "ledger"
    holder, waiter = ea.ApprovalLedger(path), ea.ApprovalLedger(path)
    entered = threading.Event()

    def contend() -> None:
        with waiter._locked():
            entered.set()

    with holder._locked():
        holder._rewrite([("d" * 64, 1)])
        thread = threading.Thread(target=contend)
        thread.start()
        assert not entered.wait(0.5), "a second consumer entered while the lock was held"
    thread.join(timeout=5)
    assert entered.is_set(), "the waiting consumer never acquired the lock after release"
