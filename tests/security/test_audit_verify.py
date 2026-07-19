"""Security tests for the deepened audit-verification tooling.

Covers ``AuditLogger.verify_report`` (structured tamper diagnosis: located
first failure, granular signature status, malformed-line fail-closed) and the
standalone ``scripts/audit_verify.py`` CLI (read-only verification with
HMAC / Ed25519-public-key schemes and fail-closed exit codes).
"""

import json
from pathlib import Path
from typing import Any

import pytest
from agents.policies.audit import AuditLogger
from scripts.audit_verify import main as verify_main

_KEY = b"test-signing-key"


def _log_with(tmp_path: Path, n: int = 3, **kwargs: Any) -> AuditLogger:
    logger = AuditLogger(tmp_path / "audit.log", **kwargs)
    for i in range(n):
        logger.record(
            actor="tester",
            action=f"action-{i}",
            action_class="read_only",
            decision="allow",
            reason="unit test",
        )
    return logger


# ------------------------------------------------------------------ report: intact
@pytest.mark.security
def test_report_intact_unsigned(tmp_path: Path) -> None:
    logger = _log_with(tmp_path)
    report = logger.verify_report()
    assert report.intact is True
    assert report.entries == 3
    assert report.head_seq == 2
    assert report.signature == "unsigned"
    assert report.failure is None
    assert report.checkpoint_seq is None
    assert logger.verify() is True  # thin wrapper agrees


@pytest.mark.security
def test_report_empty_log_with_signer_is_intact(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit.log", signing_key=_KEY)
    report = logger.verify_report()
    assert report.intact is True
    assert report.entries == 0
    assert report.signature == "empty"


# ------------------------------------------------------------------ report: tamper forensics
@pytest.mark.security
def test_report_locates_edited_entry(tmp_path: Path) -> None:
    logger = _log_with(tmp_path)
    lines = logger.path.read_text(encoding="utf-8").splitlines()
    doctored = json.loads(lines[1])
    doctored["decision"] = "deny"  # rewrite history
    lines[1] = json.dumps(doctored)
    logger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = logger.verify_report()
    assert report.intact is False
    assert report.failure is not None
    assert "entry hash mismatch" in report.failure
    assert "audit.log:2" in report.failure
    assert "seq 1" in report.failure
    assert logger.verify() is False


@pytest.mark.security
def test_report_locates_deleted_entry(tmp_path: Path) -> None:
    logger = _log_with(tmp_path)
    lines = logger.path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    logger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = logger.verify_report()
    assert report.intact is False
    assert report.failure is not None
    assert "chain break" in report.failure
    assert "expected seq 1" in report.failure


@pytest.mark.security
def test_report_malformed_line_fails_closed_not_raises(tmp_path: Path) -> None:
    # Corruption must be a located verdict, never an exception out of verify.
    logger = _log_with(tmp_path)
    with logger.path.open("a", encoding="utf-8") as fh:
        fh.write("{ not json at all\n")

    report = logger.verify_report()
    assert report.intact is False
    assert report.failure is not None
    assert "malformed entry" in report.failure
    assert "audit.log:4" in report.failure
    assert logger.verify() is False  # and the bool wrapper survives too


@pytest.mark.security
def test_report_missing_checkpoint_detected_after_prune(tmp_path: Path) -> None:
    logger = _log_with(tmp_path, n=6, max_bytes=1, retain_segments=1)
    report = logger.verify_report()
    assert report.intact is True
    assert report.checkpoint_seq is not None
    assert report.segments >= 2

    logger._checkpoint_path.unlink()  # drop the anchor for the pruned prefix
    broken = logger.verify_report()
    assert broken.intact is False
    assert broken.failure is not None
    assert "chain break" in broken.failure


# ------------------------------------------------------------------ report: signature statuses
@pytest.mark.security
def test_report_signature_statuses(tmp_path: Path) -> None:
    logger = _log_with(tmp_path, signing_key=_KEY)
    assert logger.verify_report().signature == "valid"

    sig_path = logger._sig_path
    good_sig = sig_path.read_text(encoding="utf-8")

    sig_path.unlink()
    report = logger.verify_report()
    assert (report.intact, report.signature) == (False, "missing")
    assert report.failure == "head signature missing"

    sig_path.write_text("garbage", encoding="utf-8")
    assert logger.verify_report().signature == "malformed"

    doctored = json.loads(good_sig)
    doctored["signature"] = "00" * 32
    sig_path.write_text(json.dumps(doctored), encoding="utf-8")
    assert logger.verify_report().signature == "invalid"

    # Restore, append, then put the old (now outdated) signature back: stale.
    sig_path.write_text(good_sig, encoding="utf-8")
    logger.record(
        actor="tester", action="late", action_class="read_only", decision="allow", reason="x"
    )
    sig_path.write_text(good_sig, encoding="utf-8")
    assert logger.verify_report().signature == "stale"


@pytest.mark.security
def test_report_signature_unchecked_past_chain_break(tmp_path: Path) -> None:
    logger = _log_with(tmp_path, signing_key=_KEY)
    lines = logger.path.read_text(encoding="utf-8").splitlines()
    del lines[0]
    logger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = logger.verify_report()
    assert report.intact is False
    assert report.signature == "unchecked"


# ------------------------------------------------------------------ CLI
@pytest.mark.security
def test_cli_intact_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("AUDIT_ED25519_PUBLIC_KEY", raising=False)
    logger = _log_with(tmp_path)
    assert verify_main(["--log", str(logger.path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["intact"] is True
    assert payload["signature"] == "unsigned"


@pytest.mark.security
def test_cli_tampered_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("AUDIT_ED25519_PUBLIC_KEY", raising=False)
    logger = _log_with(tmp_path)
    lines = logger.path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    logger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_main(["--log", str(logger.path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["intact"] is False
    assert "chain break" in payload["failure"]


@pytest.mark.security
def test_cli_require_signature_without_keys_exits_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("AUDIT_ED25519_PUBLIC_KEY", raising=False)
    logger = _log_with(tmp_path)
    assert verify_main(["--log", str(logger.path), "--require-signature"]) == 3


@pytest.mark.security
def test_cli_hmac_valid_and_wrong_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AUDIT_ED25519_PUBLIC_KEY", raising=False)
    logger = _log_with(tmp_path, signing_key=_KEY)

    monkeypatch.setenv("AUDIT_HMAC_KEY", _KEY.decode())
    assert verify_main(["--log", str(logger.path), "--require-signature"]) == 0
    assert json.loads(capsys.readouterr().out)["signature"] == "valid"

    monkeypatch.setenv("AUDIT_HMAC_KEY", "wrong-key")
    assert verify_main(["--log", str(logger.path)]) == 2
    assert json.loads(capsys.readouterr().out)["signature"] == "invalid"


@pytest.mark.security
def test_cli_ed25519_public_key_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # An auditor holding ONLY the public key verifies a log signed elsewhere.
    from agents.policies.signing import Ed25519Signer, generate_ed25519_keypair

    private_raw, public_raw = generate_ed25519_keypair()
    logger = _log_with(tmp_path, signer=Ed25519Signer(private_raw))

    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    monkeypatch.setenv("AUDIT_ED25519_PUBLIC_KEY", public_raw.hex())
    assert verify_main(["--log", str(logger.path), "--require-signature"]) == 0
    assert json.loads(capsys.readouterr().out)["signature"] == "valid"


# ------------------------------------------------------------------ review hardening
@pytest.mark.security
def test_report_malformed_checkpoint_fails_closed_not_raises(tmp_path: Path) -> None:
    logger = _log_with(tmp_path, n=6, max_bytes=1, retain_segments=1)
    assert logger.verify_report().intact is True
    logger._checkpoint_path.write_text("{ truncated", encoding="utf-8")
    report = logger.verify_report()
    assert report.intact is False
    assert report.failure is not None
    assert "malformed checkpoint" in report.failure
    assert logger.verify() is False


@pytest.mark.security
def test_report_undecodable_segment_fails_closed_not_raises(tmp_path: Path) -> None:
    logger = _log_with(tmp_path)
    with logger.path.open("ab") as fh:
        fh.write(b"\xff\xfe\x00garbage bytes\n")
    report = logger.verify_report()
    assert report.intact is False
    assert report.failure is not None
    assert "unreadable segment" in report.failure
    assert "audit.log" in report.failure
    assert logger.verify() is False


@pytest.mark.security
def test_logger_exists_distinguishes_missing_from_empty(tmp_path: Path) -> None:
    missing = AuditLogger(tmp_path / "nope" / "audit.log")
    assert missing.exists() is False
    empty = AuditLogger(tmp_path / "audit.log")
    empty.path.touch()
    assert empty.exists() is True


@pytest.mark.security
def test_cli_nonexistent_log_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A monitor watching a wrong or vanished path must not stay green — even
    # with a signing key set and --require-signature (the reviewer's scenario).
    monkeypatch.setenv("AUDIT_HMAC_KEY", _KEY.decode())
    monkeypatch.delenv("AUDIT_ED25519_PUBLIC_KEY", raising=False)
    missing = tmp_path / "does-not-exist" / "audit.log"
    assert verify_main(["--log", str(missing), "--require-signature"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["intact"] is False
    assert payload["failure"] == "audit log not found"


@pytest.mark.security
def test_cli_empty_existing_log_is_intact(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # An intentionally empty but existing log is the legitimate counterpart.
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("AUDIT_ED25519_PUBLIC_KEY", raising=False)
    log = tmp_path / "audit.log"
    log.touch()
    assert verify_main(["--log", str(log)]) == 0
    assert json.loads(capsys.readouterr().out)["intact"] is True
