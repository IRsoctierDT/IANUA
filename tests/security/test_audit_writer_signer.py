# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Chain writers sign with the scheme the node is configured for, Ed25519 included.

Every writer used to resolve ``signing_key_from_env``, which is HMAC-only, so a
deployment configured for Ed25519 wrote every chain head unsigned: its verifiers
(public key only) then reported every chain broken, and
``scripts/run_backup.py --verify-restore`` failed every correct restore because
its own gate decision appended an unsigned entry. ``.env.example`` already told
operators to "sign with the private key"; no writer read it.

``signer_from_env`` is the writing counterpart of ``verifier_from_env``, with
the same precedence, and both refuse key material that exists but cannot be
used. Keys are generated per test and never written anywhere (AGENTS.md §5).
"""

from __future__ import annotations

import ast
import json
import secrets
import time
from collections.abc import Callable
from pathlib import Path

import pytest

import agents.policies.signing as signing
from agents.policies.audit import AuditLogger, VerificationReport, signer_from_env, verifier_from_env
from agents.policies.signing import (
    Ed25519Signer,
    Ed25519Verifier,
    HmacSigner,
    generate_ed25519_keypair,
)
from ingest import normalize
from store import EventStore

pytestmark = pytest.mark.security

_REPO = Path(__file__).resolve().parents[2]
#: The packages AGENTS.md §7 type-checks, tests excluded.
_PRODUCTION = (
    "agents",
    "attack",
    "intel",
    "ingest",
    "store",
    "correlation",
    "pipeline",
    "collect",
    "scripts",
    "dashboard",
    "mcp",
    "rag",
    "compliance",
    "sli",
)
_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_AUDITD = "type=SYSCALL msg=audit(1760000001.200:2): node=web-01 auid=svc-deploy comm=bash"
_MESSAGE = b"head-message"
#: Not hex, so no key at all: the shape an operator's typo takes.
_UNUSABLE = "not-hex"


def _pair() -> tuple[str, str]:
    private, public = generate_ed25519_keypair()
    return private.hex(), public.hex()


def _env(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    for name, value in values.items():
        monkeypatch.setenv(name, value)


# --- resolution ---------------------------------------------------------------------


def test_nothing_configured_means_unsigned_on_both_sides() -> None:
    assert signer_from_env() is None
    assert verifier_from_env() is None


def test_hmac_wins_on_both_sides_when_both_schemes_are_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same precedence ``verifier_from_env`` always had, now on the writing side too."""
    private, public = _pair()
    _env(
        monkeypatch,
        AUDIT_HMAC_KEY=secrets.token_hex(32),
        AUDIT_ED25519_PRIVATE_KEY=private,
        AUDIT_ED25519_PUBLIC_KEY=public,
    )
    assert isinstance(signer_from_env(), HmacSigner)
    assert isinstance(verifier_from_env(), HmacSigner)


def test_a_private_key_signs_and_its_public_half_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private, public = _pair()
    _env(monkeypatch, AUDIT_ED25519_PRIVATE_KEY=private, AUDIT_ED25519_PUBLIC_KEY=public)
    signer, verifier = signer_from_env(), verifier_from_env()
    assert isinstance(signer, Ed25519Signer)
    assert isinstance(verifier, Ed25519Verifier), "the public key is the least capability"
    assert verifier.verify(_MESSAGE, signer.sign(_MESSAGE))


def test_a_private_key_alone_verifies_what_it_signs(monkeypatch: pytest.MonkeyPatch) -> None:
    """A writing node need not configure the public key a second time.

    Before, ``verifier_from_env`` read only the public key, so a node holding just
    the private key verified chain-only (``unsigned``) and never checked a signature.
    """
    private, _ = _pair()
    _env(monkeypatch, AUDIT_ED25519_PRIVATE_KEY=private)
    signer, verifier = signer_from_env(), verifier_from_env()
    assert signer is not None and verifier is not None
    assert verifier.verify(_MESSAGE, signer.sign(_MESSAGE))


def test_a_public_key_alone_verifies_and_cannot_sign(monkeypatch: pytest.MonkeyPatch) -> None:
    _, public = _pair()
    _env(monkeypatch, AUDIT_ED25519_PUBLIC_KEY=public)
    assert signer_from_env() is None
    assert isinstance(verifier_from_env(), Ed25519Verifier)


@pytest.mark.security
def test_find_record_matches_the_same_captured_bytes_it_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post-verification replacement cannot inject a record into the lookup."""
    chain = tmp_path / "audit.log"
    signed = AuditLogger(chain, signing_key=secrets.token_bytes(32))
    signed.record(
        actor="test",
        action="backup_state:take:1",
        action_class="read_only",
        decision="allow",
        reason="manifest sha256 original",
    )
    signed._lock_path.unlink()
    capture_snapshot = AuditLogger._verify_snapshot_locked

    def replace_after_snapshot(
        logger: AuditLogger, *, capture_segments: bool
    ) -> tuple[VerificationReport, list[tuple[Path, str]]]:
        report, segment_texts = capture_snapshot(logger, capture_segments=capture_segments)
        AuditLogger(chain).record(
            actor="test",
            action="backup_state:take:1",
            action_class="read_only",
            decision="allow",
            reason="manifest sha256 forged",
        )
        return report, segment_texts

    monkeypatch.setattr(AuditLogger, "_verify_snapshot_locked", replace_after_snapshot)
    report, found = signed.find_record(
        lambda event: str(event.get("reason", "")).endswith("manifest sha256 forged")
    )

    assert report.intact and report.signature == "valid"
    assert not found


# --- refusals -----------------------------------------------------------------------


def test_a_pair_that_is_not_one_pair_is_refused_on_both_sides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One half rotated and not the other: every chain would read ``invalid``."""
    private, _ = _pair()
    _, other_public = _pair()
    _env(monkeypatch, AUDIT_ED25519_PRIVATE_KEY=private, AUDIT_ED25519_PUBLIC_KEY=other_public)
    for resolve in (signer_from_env, verifier_from_env):
        with pytest.raises(ValueError, match="not one key pair") as caught:
            resolve()
        assert private not in str(caught.value) and other_public not in str(caught.value)


@pytest.mark.parametrize(
    "value",
    ["not-hex", "ab" * 31, "ab" * 33],
    ids=["not-hex", "short", "long"],
)
def test_an_unusable_private_key_is_refused_not_ignored(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Writers ignored this variable entirely, so a broken one was never noticed."""
    _env(monkeypatch, AUDIT_ED25519_PRIVATE_KEY=value)
    with pytest.raises(ValueError) as caught:
        signer_from_env()
    assert value not in str(caught.value), "key material must not reach an error message"
    with pytest.raises(ValueError):
        verifier_from_env()


def test_ed25519_without_the_crypto_extra_is_a_value_error_for_writers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ValueError`` is what every writer already turns into a refusal to run.

    ``RuntimeError`` would have escaped all four CLIs' ``except (OSError, ValueError)``
    as a traceback.
    """
    private, _ = _pair()
    _env(monkeypatch, AUDIT_ED25519_PRIVATE_KEY=private)

    def missing() -> None:
        raise RuntimeError("Ed25519 signing requires the optional 'cryptography' dependency")

    monkeypatch.setattr(signing, "_load_ed25519", missing)
    with pytest.raises(ValueError, match="cryptography"):
        signer_from_env()


# --- every writer, end to end ---------------------------------------------------------


def _seed(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(5):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(now + index))


def _cli(main: Callable[[list[str]], int], argv: list[str], refused: bool) -> None:
    assert main(argv) == (1 if refused else 0)


def _backup(root: Path, tmp: Path, refused: bool) -> tuple[Path, ...]:
    from scripts.run_backup import main

    _seed(root)
    _cli(main, ["--root", str(root), "--caller", "test"], refused)
    return (root / "data" / "events" / "audit.log",)


def _retention(root: Path, tmp: Path, refused: bool) -> tuple[Path, ...]:
    from scripts.run_retention import main

    _seed(root)
    _cli(main, ["--root", str(root), "--caller", "test"], refused)
    return (root / "data" / "events" / "audit.log",)


def _pipeline(root: Path, tmp: Path, refused: bool) -> tuple[Path, ...]:
    from scripts.run_pipeline import main

    _seed(root)
    _cli(main, ["--root", str(root)], refused)
    return (root / "data" / "pipeline" / "audit.log",)


def _collector(root: Path, tmp: Path, refused: bool) -> tuple[Path, ...]:
    from scripts.run_collector import main

    root.mkdir(parents=True, exist_ok=True)
    logs = tmp / "logs"
    logs.mkdir()
    source = logs / "audit.log"
    source.write_text(_AUDITD + "\n", encoding="utf-8")
    _cli(main, ["--root", str(root), "--source", str(source)], refused)
    return (root / "data" / "collect" / "audit.log",)


def _compliance(root: Path, tmp: Path, refused: bool) -> tuple[Path, ...]:
    from compliance.controls import Category, CheckResult, Control, ControlStatus, Severity
    from compliance.engine import run_controls
    from compliance.evidence import record_run

    root.mkdir(parents=True, exist_ok=True)
    control = Control(
        id="T-01",
        title="Test control",
        description="d",
        category=Category.POLICY,
        severity=Severity.LOW,
        check=lambda _root: CheckResult(ControlStatus.PASS, "ok"),
    )
    report = run_controls(root, controls=(control,))
    if refused:
        with pytest.raises(ValueError):
            record_run(report, root=root)
    else:
        record_run(report, root=root)
    evidence = root / "data" / "compliance"
    return evidence / "audit.log", evidence / "evidence.jsonl"


#: Each writer, run with or without an expected refusal; returns the chain it
#: writes first, then any other file a run of it appends to.
_WRITERS: dict[str, Callable[[Path, Path, bool], tuple[Path, ...]]] = {
    "run_backup": _backup,
    "run_retention": _retention,
    "run_pipeline": _pipeline,
    "run_collector": _collector,
    "compliance.evidence": _compliance,
}


@pytest.mark.parametrize("writer", sorted(_WRITERS))
def test_every_writer_refuses_unusable_key_material_before_writing_anything(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, writer: str
) -> None:
    """A refused configuration leaves nothing behind: no chain, and no unchained record.

    The CLIs resolve the signer before their first write and exit 1 with a
    message. ``compliance.evidence`` resolved it only after appending every
    control result to ``evidence.jsonl`` — measured: the caller was told the run
    was refused while ``score_history`` counted it as a real one. Found by review.
    """
    _env(monkeypatch, AUDIT_ED25519_PRIVATE_KEY=_UNUSABLE)
    written = _WRITERS[writer](tmp_path / "root", tmp_path, True)
    err = capsys.readouterr().err
    if writer != "compliance.evidence":
        assert "audit log unusable, refusing to run" in err and "Traceback" not in err, err
    left = [str(path.relative_to(tmp_path)) for path in written if path.exists()]
    assert left == [], f"{writer} wrote before refusing: {left}"


@pytest.mark.parametrize("writer", sorted(_WRITERS))
def test_every_writer_signs_with_ed25519_when_that_is_the_configured_scheme(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writer: str
) -> None:
    """The property the gap broke: a chain an Ed25519 node writes verifies under its public key.

    The writer is given the private key and nothing else; the chain is then
    verified with a public-key-only verifier, the way an auditor or a passive node
    holding no secret would read it. Measured before the fix: ``missing`` from
    every writer, because none of them read the private key.
    """
    private, public = _pair()
    _env(monkeypatch, AUDIT_ED25519_PRIVATE_KEY=private)
    chain, *_ = _WRITERS[writer](tmp_path / "root", tmp_path, False)
    assert chain.is_file(), f"{writer} wrote no chain at {chain}"

    report = AuditLogger(chain, signer=Ed25519Verifier(bytes.fromhex(public))).verify_report()
    assert report.signature == "valid", (writer, report.signature, report.failure)
    assert report.intact and report.entries >= 1, report
    sidecar = json.loads(chain.with_name(chain.name + ".sig").read_text(encoding="utf-8"))
    assert sidecar["algo"] == "ed25519", sidecar


def test_no_production_writer_resolves_the_hmac_only_key() -> None:
    """``signing_key=`` is the HMAC-only path; a writer passing it cannot sign Ed25519.

    Asserted over the AST of every production module, so a new writer that copies
    the old line goes red here instead of writing unsigned chains on Ed25519 nodes.
    """
    offenders: list[str] = []
    for package in _PRODUCTION:
        for path in sorted((_REPO / package).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                if name == "AuditLogger" and any(k.arg == "signing_key" for k in node.keywords):
                    offenders.append(f"{path.relative_to(_REPO)}:{node.lineno}")
    assert offenders == [], offenders


#: Dashboard calls that resolve audit key material and so raise ``ValueError``
#: on an unusable or mismatched key (``signer_from_env``/``verifier_from_env``).
_KEYED_CALLS = frozenset({"record_run", "verify_chain"})


def _catches_value_error(handler: ast.ExceptHandler) -> bool:
    caught = handler.type
    names = caught.elts if isinstance(caught, ast.Tuple) else [caught]
    return any(isinstance(name, ast.Name) and name.id == "ValueError" for name in names)


def _unguarded_keyed_calls(node: ast.AST, guarded: bool, out: list[int]) -> None:
    if isinstance(node, ast.Try):
        body_guarded = guarded or any(_catches_value_error(h) for h in node.handlers)
        for statement in node.body:
            _unguarded_keyed_calls(statement, body_guarded, out)
        outside: list[ast.AST] = [*node.handlers, *node.orelse, *node.finalbody]
        for part in outside:
            _unguarded_keyed_calls(part, guarded, out)
        return
    if isinstance(node, ast.Call):
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name in _KEYED_CALLS and not guarded:
            out.append(node.lineno)
    for child in ast.iter_child_nodes(node):
        _unguarded_keyed_calls(child, guarded, out)


def test_the_dashboard_reports_a_refused_key_instead_of_a_traceback() -> None:
    """Every keyed compliance call in the dashboard sits in a ``try`` that catches ``ValueError``.

    Asserted over the AST because the dashboard cannot be run under pytest
    (Streamlit is not a test dependency). Guarding only ``record_run`` was not
    enough: the evidence trail's ``verify_chain`` resolves the verifier on the
    same render and raised the same ``ValueError`` as a traceback. Found by review.
    """
    path = _REPO / "dashboard" / "app.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (node.func.id if isinstance(node.func, ast.Name) else "") in _KEYED_CALLS
    ]
    assert {c.func.id for c in calls if isinstance(c.func, ast.Name)} == _KEYED_CALLS, (
        "the guard has nothing to check; update _KEYED_CALLS"
    )
    unguarded: list[int] = []
    _unguarded_keyed_calls(tree, False, unguarded)
    assert unguarded == [], [f"dashboard/app.py:{line}" for line in unguarded]
