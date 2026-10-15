# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The job that rotates and prunes the audit log must verify at least as much
as the job that only reads it.

:mod:`scripts.audit_maintenance` is the only thing in the platform that
*deletes* tamper-evident evidence: rotation archives the active log and pruning
unlinks the oldest segments, advancing a ``.checkpoint`` past what it cut. Its
read-only sibling :mod:`scripts.audit_verify` has long failed closed in two
ways that this one did not:

* **A path with no log at it.** ``verify()`` on a nonexistent log returns
  ``True`` — an empty chain is a valid chain — so the maintainer printed
  ``{"verified": true}`` and exited **0** for a log that was never there,
  building the whole wrong path at the umask on its way out via
  ``apply_retention``'s ``mkdir(parents=True)``. A nightly job pointed at a
  typo stayed green indefinitely. Its own documented cron line pointed at
  ``data/audit.log``, which no writer in the platform creates: there is one
  chain per subsystem. The example *was* the typo.
* **Key material it never read.** It resolved only ``AUDIT_HMAC_KEY``, so on
  an Ed25519-signed chain — the scheme whose whole point is that a verifier
  holds only the public key — it configured no signer at all, reported the head
  signature as ``unsigned``, verified the chain alone, and rotated. A stale or
  forged head signature could not stop it, because it never looked.

Both are now resolved through one shared
:func:`agents.policies.audit.verifier_from_env`, and the refusal uses the same
exit code and the same ``failure`` text as the verifier, so a monitor watching
either gets one answer. The tests below assert the refusals *and* that an
intentionally empty-but-existing log is still maintained normally — the
distinction is the whole value of the check.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from agents.policies import AuditLogger
from scripts.audit_maintenance import main as maintain_main
from scripts.audit_verify import main as verify_main

_HMAC_KEY = b"maintenance-failclosed-test-key"


@pytest.fixture(autouse=True)
def _no_ambient_key_material(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Neither scheme leaks in from the developer's or runner's environment."""
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("AUDIT_ED25519_PUBLIC_KEY", raising=False)
    yield


def _emit(logger: AuditLogger, n: int) -> None:
    for i in range(n):
        logger.record(
            actor="mcp", action=f"a{i}", action_class="read_only", decision="allow", reason="ok"
        )


# ------------------------------------------------------- a path with no log
@pytest.mark.security
def test_a_missing_log_is_refused_and_nothing_is_created(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2, and not one directory of the wrong path brought into being."""
    missing = tmp_path / "deep" / "nested" / "typo" / "audit.log"

    code = maintain_main(
        ["--log", str(missing), "--max-bytes", "1048576", "--retain-segments", "7"]
    )

    assert code == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.err)
    assert payload["verified"] is False
    assert payload["failure"] == "audit log not found"
    assert payload["action"] == "aborted"
    assert captured.out == "", "a refusal must not also print a success summary"
    # The guard has to run *before* apply_retention, not merely before the
    # exit: that mkdir(parents=True) is what used to build the typo'd path,
    # and only its leaf got the owner-only mode.
    assert not (tmp_path / "deep").exists()


@pytest.mark.security
def test_no_verify_does_not_skip_the_existence_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--no-verify`` opts out of verifying a chain, not out of having one.

    It is also the flag an operator reaches for when a scheduled job keeps
    failing — exactly the moment a wrong path must not go quiet.
    """
    missing = tmp_path / "deep" / "typo" / "audit.log"

    assert maintain_main(["--log", str(missing), "--no-verify"]) == 2
    assert json.loads(capsys.readouterr().err)["failure"] == "audit log not found"
    assert not (tmp_path / "deep").exists()


@pytest.mark.security
def test_an_empty_but_existing_log_is_still_maintained(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The legitimate counterpart: nothing logged yet is not a wrong path."""
    log = tmp_path / "audit.log"
    log.touch()

    assert maintain_main(["--log", str(log), "--max-bytes", "1048576"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verified"] is True
    assert payload["rotated"] is False


@pytest.mark.security
def test_an_archive_only_chain_counts_as_existing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Rotation moves the active log aside; the chain still exists.

    A guard that only checked ``path.exists()`` would refuse to maintain a log
    immediately after it rotated — turning the fail-closed fix into an outage
    on exactly the chains that need pruning most.
    """
    log = tmp_path / "audit.log"
    _emit(AuditLogger(log, max_bytes=1), 2)  # each record rotates
    log.unlink(missing_ok=True)
    assert list(tmp_path.glob("audit.log.[0-9]*")), "fixture must leave only archives"

    assert maintain_main(["--log", str(log), "--retain-segments", "5"]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True


@pytest.mark.security
def test_the_maintainer_and_the_verifier_agree_on_a_missing_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One path, two tools, one answer — a monitor may watch either."""
    missing = tmp_path / "gone" / "audit.log"

    assert maintain_main(["--log", str(missing)]) == 2
    maintainer = json.loads(capsys.readouterr().err)
    assert verify_main(["--log", str(missing)]) == 2
    verifier = json.loads(capsys.readouterr().out)

    assert maintainer["failure"] == verifier["failure"] == "audit log not found"


# ------------------------------------------------- a path that is not a chain
@pytest.mark.security
def test_a_directory_at_the_log_path_is_refused_and_not_rotated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The worst defect this CLI had: rotation renaming a whole directory.

    A ``--log`` one component short of the log names the subsystem directory.
    ``exists()`` used to accept it (every discovery tested ``Path.exists()``,
    true of a directory), ``_should_rotate`` agreed (a directory's ``st_size``
    is its own block size, so any small ``--max-bytes`` qualified), and
    ``_rotate`` **renamed the directory** to ``<name>.1`` — audit chain,
    cursor and all — reporting ``{"rotated": true}`` at exit 0. With
    ``--log …/data`` it took the whole lab-data root, event store included.
    The run after that tracebacked out of ``_prune``'s ``unlink()`` with exit
    1, so the only notice an operator got arrived after the rename.

    Asserted on the tree, not just the exit code: a guard that refused *after*
    ``apply_retention`` would still pass an exit-code-only test.
    """
    subsystem = tmp_path / "data" / "pipeline"
    subsystem.mkdir(parents=True)
    _emit(AuditLogger(subsystem / "audit.log"), 3)
    (subsystem / "cursor.json").write_text("{}", encoding="utf-8")
    before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}

    code = maintain_main(
        ["--log", str(subsystem), "--no-verify", "--max-bytes", "1", "--retain-segments", "7"]
    )

    assert code == 2
    payload = json.loads(capsys.readouterr().err)
    assert payload["failure"] == (
        "path exists but is not an audit log (expected a regular, non-symlink file)"
    )
    assert {path.relative_to(tmp_path) for path in tmp_path.rglob("*")} == before, (
        "a refused maintenance pass renamed something"
    )


@pytest.mark.security
def test_the_lab_data_root_at_the_log_path_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One component shorter still, and the blast radius is every subsystem."""
    root = tmp_path / "data"
    (root / "events").mkdir(parents=True)
    (root / "events" / "events.sqlite3").write_bytes(b"x" * 64)
    before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}

    assert maintain_main(["--log", str(root), "--no-verify", "--max-bytes", "1"]) == 2
    assert "not an audit log" in json.loads(capsys.readouterr().err)["failure"]
    assert {path.relative_to(tmp_path) for path in tmp_path.rglob("*")} == before


@pytest.mark.security
def test_a_symlink_at_the_log_path_is_not_a_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """§5 states that discipline for the logs ``collect/`` reads; a chain is no different.

    A link at the chain means the chain is not where it is believed to be —
    and rotation would move the link rather than the log.
    """
    real = tmp_path / "elsewhere.log"
    _emit(AuditLogger(real), 2)
    link = tmp_path / "audit.log"
    link.symlink_to(real)

    assert maintain_main(["--log", str(link), "--max-bytes", "1"]) == 2
    assert "not an audit log" in json.loads(capsys.readouterr().err)["failure"]
    assert link.is_symlink(), "the refused pass must not have moved the link"


@pytest.mark.security
def test_apply_retention_on_a_directory_does_nothing_at_the_library_level(
    tmp_path: Path,
) -> None:
    """The same invariant one layer down, where the CLI's guard does not reach.

    Found by a plant: reverting ``_should_rotate`` to ``self.path.exists()``
    left the CLI test above green, because the CLI refuses before
    ``apply_retention`` is ever called. ``AuditLogger`` is public API
    (re-exported from ``agents.policies``), so the hardening has to hold for a
    caller that does not go through ``scripts.audit_maintenance`` — which is
    the whole reason the fix lives in the library rather than in the CLI.

    A directory's ``st_size`` is its own block size, 4096 on ext4, so any
    ``max_bytes`` below that made a mistyped path "due for rotation".
    """
    subsystem = tmp_path / "data" / "pipeline"
    subsystem.mkdir(parents=True)
    (subsystem / "cursor.json").write_text("{}", encoding="utf-8")
    before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}

    summary = AuditLogger(subsystem, max_bytes=1, retain_segments=7).apply_retention()

    assert summary["rotated"] is False, "a directory was treated as a log due for rotation"
    assert {path.relative_to(tmp_path) for path in tmp_path.rglob("*")} == before


@pytest.mark.security
def test_a_directory_named_like_an_archive_is_not_counted_as_a_segment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Archive discovery matches on the *name*; the shape has to be checked too.

    Without this, ``audit.log.1`` as a directory joins the chain, and pruning
    reaches it with ``unlink()`` — which raises rather than deletes, turning a
    scheduled job into a traceback at exit 1 against a contract that says 2.
    """
    log = tmp_path / "audit.log"
    _emit(AuditLogger(log), 2)
    (tmp_path / "audit.log.1").mkdir()
    before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}

    assert maintain_main(["--log", str(log), "--retain-segments", "0"]) == 0
    assert json.loads(capsys.readouterr().out)["archives"] == 0, "a directory joined the chain"
    assert {path.relative_to(tmp_path) for path in tmp_path.rglob("*")} == before


# -------------------------------------------------------- the signing scheme
@pytest.mark.security
def test_an_ed25519_head_signature_is_checked_before_rotating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A stale head signature stops the rotation it used to sail through.

    Asymmetric signing is the scheme where the verifier deliberately holds only
    the public key, so resolving *only* ``AUDIT_HMAC_KEY`` meant the maintainer
    silently fell back to a chain-only check on precisely the deployment that
    chose the stronger scheme.
    """
    pytest.importorskip("cryptography")  # the optional .[crypto] extra
    from agents.policies import Ed25519Signer, generate_ed25519_keypair

    private, public = generate_ed25519_keypair()
    log = tmp_path / "audit.log"
    _emit(AuditLogger(log, signer=Ed25519Signer(private)), 3)
    # Append without the key: the chain stays continuous, the head moves on,
    # and the detached signature now covers an older head.
    _emit(AuditLogger(log), 1)
    before = log.read_bytes()
    monkeypatch.setenv("AUDIT_ED25519_PUBLIC_KEY", public.hex())

    code = maintain_main(["--log", str(log), "--max-bytes", "1", "--retain-segments", "5"])

    assert code == 2
    assert json.loads(capsys.readouterr().err)["verified"] is False
    assert log.read_bytes() == before, "a log that did not verify was rotated anyway"
    assert not list(tmp_path.glob("audit.log.[0-9]*"))


@pytest.mark.security
def test_a_current_ed25519_signature_still_permits_maintenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The check must not merely refuse everything it cannot parse."""
    pytest.importorskip("cryptography")
    from agents.policies import Ed25519Signer, generate_ed25519_keypair

    private, public = generate_ed25519_keypair()
    log = tmp_path / "audit.log"
    _emit(AuditLogger(log, signer=Ed25519Signer(private)), 3)
    monkeypatch.setenv("AUDIT_ED25519_PUBLIC_KEY", public.hex())

    assert maintain_main(["--log", str(log), "--retain-segments", "5"]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True


@pytest.mark.security
def test_a_current_hmac_signature_still_permits_maintenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """HMAC wins when both are configured, and behaves as it always did."""
    log = tmp_path / "audit.log"
    _emit(AuditLogger(log, signing_key=_HMAC_KEY), 3)
    monkeypatch.setenv("AUDIT_HMAC_KEY", _HMAC_KEY.decode())

    assert maintain_main(["--log", str(log), "--retain-segments", "5"]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True


@pytest.mark.security
def test_unusable_key_material_is_refused_not_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Key material that exists but cannot be used must not degrade to a pass.

    Exit 3 (bad configuration), not 0: a maintainer that shrugged off an
    unreadable key would rotate the log while reporting ``verified: true``.
    """
    log = tmp_path / "audit.log"
    _emit(AuditLogger(log), 2)
    monkeypatch.setenv("AUDIT_ED25519_PUBLIC_KEY", "not-hex")

    assert maintain_main(["--log", str(log), "--max-bytes", "1"]) == 3
    assert "invalid signing configuration" in capsys.readouterr().err
    assert not list(tmp_path.glob("audit.log.[0-9]*")), "refused config must not rotate"


@pytest.mark.security
def test_bad_retention_arguments_still_exit_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Splitting the two configuration failures kept both diagnosable."""
    assert maintain_main(["--log", str(tmp_path / "audit.log"), "--max-bytes", "0"]) == 3
    err = capsys.readouterr().err
    assert "invalid configuration" in err
    assert "signing" not in err
