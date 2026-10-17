# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Control registry — automated, offline checks over IANUA's own posture.

Each :class:`Control` either carries a ``check`` callable (automated: reads the
repository read-only and returns a :class:`CheckResult`) or is a **manual
attestation** control (``check is None``) for properties that cannot be
verified offline (e.g. GitHub branch protection). Manual controls surface in
the UI as "requires attestation" rather than silently passing — the honest,
Vanta-style treatment.

Security considerations:
- Every check validates that it only reads inside the supplied repository
  root; no check performs network I/O, writes, or shells out.
- Check failures **fail closed**: an unexpected exception becomes
  ``ControlStatus.ERROR`` (surfaced as non-passing), never a silent pass.
- Result details contain relative paths and counts only — never file
  contents, environment values, or secrets (AGENTS.md §5).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from compliance.frameworks import Framework, FrameworkRef
from sli import MEASURERS, OBJECTIVES, Status


class ControlStatus(Enum):
    """Outcome of evaluating a control."""

    PASS = "pass"  # noqa: S105  # nosec B105 — status token, not a credential
    FAIL = "fail"
    ERROR = "error"  # check crashed — treated as non-passing (fail closed)
    MANUAL = "manual"  # requires human attestation; cannot be auto-verified
    ATTESTED = "attested"  # manual control with a current human attestation


class Category(Enum):
    """Control grouping shown in the dashboard."""

    POLICY = "Policy & Governance"
    AUDIT = "Audit & Monitoring"
    SECRETS = "Secrets & Data Protection"
    SUPPLY_CHAIN = "Supply Chain"
    CI_CD = "CI/CD & Change Management"
    TESTING = "Security Testing"
    CONFIGURATION = "Secure Configuration"


class Severity(Enum):
    """Impact if the control is failing."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one automated check (status + human-readable detail)."""

    status: ControlStatus
    detail: str


@dataclass(frozen=True)
class Control:
    """One compliance control: metadata, framework refs, optional check."""

    id: str
    title: str
    description: str
    category: Category
    severity: Severity
    framework_refs: frozenset[FrameworkRef] = field(default_factory=frozenset)
    check: Callable[[Path], CheckResult] | None = None
    attestation_hint: str = ""

    @property
    def automated(self) -> bool:
        """True when the control is evaluated by code rather than a human."""
        return self.check is not None


def _resolve_inside(root: Path, relative: str) -> Path:
    """Resolve ``relative`` under ``root``, refusing escapes (fail closed)."""
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"path escapes repository root: {relative!r}")
    return candidate


def _read_text(root: Path, relative: str, limit: int = 1_000_000) -> str | None:
    """Read a repo file as text, or ``None`` if absent/unreadable/oversized."""
    path = _resolve_inside(root, relative)
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# --- automated checks -------------------------------------------------------

_GATED = {"require_approval", "deny"}


def _load_policy(root: Path) -> dict[str, str] | None:
    text = _read_text(root, "agents/policies/policy.json")
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    policy = data.get("policy")
    if not isinstance(policy, dict):
        return None
    return {str(k): str(v) for k, v in policy.items()}


def check_policy_default_deny(root: Path) -> CheckResult:
    """Boundary crossings are denied and unknown actions are gated."""
    policy = _load_policy(root)
    if policy is None:
        return CheckResult(ControlStatus.FAIL, "agents/policies/policy.json missing or malformed")
    problems = []
    if policy.get("boundary_crossing") != "deny":
        problems.append("boundary_crossing is not 'deny'")
    if policy.get("unknown") not in _GATED:
        problems.append("unknown actions are not gated")
    if problems:
        return CheckResult(ControlStatus.FAIL, "; ".join(problems))
    return CheckResult(
        ControlStatus.PASS, "boundary_crossing=deny; unknown actions require approval"
    )


def check_approval_gates(root: Path) -> CheckResult:
    """Irreversible/external action classes require human approval."""
    policy = _load_policy(root)
    if policy is None:
        return CheckResult(ControlStatus.FAIL, "agents/policies/policy.json missing or malformed")
    gated_classes = ("destructive", "external_network", "deployment", "secret_handling")
    ungated = [c for c in gated_classes if policy.get(c) not in _GATED]
    if ungated:
        return CheckResult(ControlStatus.FAIL, f"action classes not gated: {', '.join(ungated)}")
    return CheckResult(ControlStatus.PASS, f"all {len(gated_classes)} action classes gated")


def check_audit_logging_present(root: Path) -> CheckResult:
    """Tamper-evident audit logging is implemented and security-tested."""
    module = _read_text(root, "agents/policies/audit.py")
    if module is None or "entry_hash" not in module:
        return CheckResult(ControlStatus.FAIL, "hash-chained audit logger not found")
    tests_dir = _resolve_inside(root, "tests/security")
    audit_tests = (
        sorted(p.name for p in tests_dir.glob("test_audit_*.py")) if tests_dir.is_dir() else []
    )
    if not audit_tests:
        return CheckResult(ControlStatus.FAIL, "no tests/security/test_audit_*.py coverage")
    return CheckResult(
        ControlStatus.PASS,
        f"hash-chained logger present with {len(audit_tests)} security test module(s)",
    )


def check_self_monitoring_defined(root: Path) -> CheckResult:
    """The platform's own service level is defined, derived, and fails closed.

    Structural, and deliberately separate from whether the objectives are
    currently *met*: a framework asks both "is there monitoring" and "is it
    green", and conflating them means a platform with no monitoring at all
    reports the same as one that is simply healthy.

    Three properties, each of which has been a defect somewhere in this
    repository rather than a hypothetical:

    * every objective has a measurer and every measurer an objective — the
      shape that let ``EventStore.prune`` ship with no caller at all;
    * every target records where its number came from, so a threshold is not
      something the next engineer either dare not change or changes blind;
    * an unmeasurable indicator is **not** healthy. ``DESIGN.md`` §11 records
      three signals that read healthy while the subsystem behind them was
      not, and this is the assertion that the lesson is still implemented.
    """
    del root  # Definitional: it reads the committed objective table, not the tree.
    objective_ids = {objective.id for objective in OBJECTIVES}
    missing = sorted(objective_ids - set(MEASURERS))
    orphaned = sorted(set(MEASURERS) - objective_ids)
    unexplained = sorted(objective.id for objective in OBJECTIVES if not objective.rationale)
    if missing or orphaned or unexplained:
        return CheckResult(
            ControlStatus.FAIL,
            f"objectives without a measurer: {missing or 'none'}; "
            f"measurers without an objective: {orphaned or 'none'}; "
            f"targets with no recorded derivation: {unexplained or 'none'}",
        )
    if Status.UNKNOWN.healthy:
        return CheckResult(
            ControlStatus.FAIL,
            "an unmeasurable indicator counts as healthy; the monitoring fails open",
        )
    return CheckResult(
        ControlStatus.PASS,
        f"{len(OBJECTIVES)} service-level objective(s) defined, each with a "
        f"recorded derivation; an unmeasurable indicator is not a pass",
    )


def check_secret_hygiene(root: Path) -> CheckResult:
    """.env is gitignored and .env.example documents keys without values."""
    gitignore = _read_text(root, ".gitignore") or ""
    lines = {line.strip() for line in gitignore.splitlines()}
    problems = []
    if not any(entry in lines for entry in (".env", "*.env", ".env*")):
        problems.append(".env is not gitignored")
    example = _read_text(root, ".env.example")
    if example is None:
        problems.append(".env.example is missing")
    else:
        leaky = [
            line.split("=", 1)[0]
            for line in example.splitlines()
            if re.match(r"^[A-Z0-9_]+=\S{24,}$", line.strip())
        ]
        if leaky:
            problems.append(f"value-bearing keys in .env.example: {', '.join(sorted(leaky)[:3])}")
    if problems:
        return CheckResult(ControlStatus.FAIL, "; ".join(problems))
    return CheckResult(ControlStatus.PASS, ".env gitignored; .env.example documents keys only")


def check_lab_data_isolated(root: Path) -> CheckResult:
    """Local/lab data (data/) is excluded from version control."""
    gitignore = _read_text(root, ".gitignore") or ""
    lines = {line.strip() for line in gitignore.splitlines()}
    if any(entry in lines for entry in ("data/", "/data/", "data", "/data")):
        return CheckResult(ControlStatus.PASS, "data/ is gitignored")
    return CheckResult(ControlStatus.FAIL, "data/ is not listed in .gitignore")


def check_dependency_lock(root: Path) -> CheckResult:
    """Dependencies resolve from a committed lockfile."""
    lock = _resolve_inside(root, "uv.lock")
    if lock.is_file() and lock.stat().st_size > 0:
        return CheckResult(ControlStatus.PASS, "uv.lock present (dependency source of truth)")
    return CheckResult(ControlStatus.FAIL, "uv.lock missing or empty")


def check_sbom_present(root: Path) -> CheckResult:
    """A software bill of materials is generated and committed."""
    sbom_dir = _resolve_inside(root, "security/sbom")
    if sbom_dir.is_dir():
        sboms = sorted(p.name for p in sbom_dir.glob("*.json"))
        if sboms:
            return CheckResult(
                ControlStatus.PASS, f"{len(sboms)} SBOM document(s) in security/sbom/"
            )
    return CheckResult(ControlStatus.FAIL, "no SBOM documents under security/sbom/")


def _own_attack_package() -> Path:
    """The one ``attack`` package SUP-03 may load: the one beside ``compliance/``.

    Located from this module's own file, never from ``sys.path`` or the working
    directory, so the answer does not move with how the process was started.
    """
    return Path(__file__).resolve().parent.parent / "attack"


def _attack_import_is_own_package() -> bool:
    """Whether ``import attack`` would bind to :func:`_own_attack_package`.

    :func:`importlib.util.find_spec` locates a top-level module without
    executing it — measured: a planted ``attack/__init__.py`` in the working
    directory was located and did not run. Fails closed: no spec, a namespace
    package (no origin), an unreadable spec, or an origin anywhere other than
    the sibling package all answer ``False``. The import is function-local for
    the reason given in :func:`check_attack_corpus_integrity`.
    """
    import importlib.util

    try:
        spec = importlib.util.find_spec("attack")
    except (ImportError, ValueError):
        return False
    if spec is None or spec.origin is None:
        return False
    return Path(spec.origin).resolve().parent == _own_attack_package()


def check_attack_corpus_integrity(root: Path) -> CheckResult:
    """SUP-03: committed ATT&CK shards verify against the pin, offline.

    Read-only and fail closed: a missing pin, a hash mismatch, or a corpus
    that does not load is a FAIL — never a silent pass. Runs the same loader
    the platform uses, so the control is load-bearing, not decorative.

    ``root`` is **data, never a code path** — enforced here, not inherited
    from the interpreter. The loader is this installation's own :mod:`attack`
    package, the one beside ``compliance/``; only the pin and the shards are
    read from under ``root``. Before importing, the check asks the import
    system *where* ``attack`` would come from, without running it, and
    returns ``ERROR`` if the answer is anywhere else. Two earlier versions of
    this function were measured short of that sentence: the first inserted
    ``root`` at the front of ``sys.path`` and executed a planted
    ``attack/__init__.py`` under any root; the second removed the insert but
    still imported from ``sys.path`` as it stood, so with the graded tree as
    the working directory under ``python -c``/``-m`` (where ``''`` is
    ``sys.path[0]``) a planted package under ``root`` ran and forged a PASS.

    What this does not hold: a shadowing ``attack`` that something *else*
    imported before this check ran is detected and refused, but that code has
    already run. Only this loader is guarded; nothing here changes how a
    module-level import in this file resolves at import time.

    The imports stay function-local on purpose: a module-level line above
    ``Category.SECRETS`` shifts an accepted ``.secrets.baseline`` entry.
    """
    if not _attack_import_is_own_package():
        return CheckResult(
            ControlStatus.ERROR,
            "ATT&CK corpus not evaluated: `import attack` would not bind to this "
            "installation's own package, so the loader was not imported.",
        )
    from attack import load_corpus, load_pin

    try:
        pin = load_pin(root / "attack" / "pins" / "enterprise-attack.pin.json")
        corpus = load_corpus(pin=pin, data_dir=root / "attack" / "data")
    except Exception as exc:
        return CheckResult(ControlStatus.FAIL, f"ATT&CK corpus failed verification: {exc}")
    signed = "signed pin" if pin.signature is not None else "unsigned pin (corruption-only claim)"
    return CheckResult(
        ControlStatus.PASS,
        f"ATT&CK {corpus.attack_version}: {len(corpus.techniques)} techniques, "
        f"{len(corpus.tombstones)} tombstones verified against {signed}.",
    )


def check_ci_gates(root: Path) -> CheckResult:
    """CI enforces lint, types, SAST, and tests on every change."""
    ci = _read_text(root, ".github/workflows/ci.yml")
    if ci is None:
        return CheckResult(ControlStatus.FAIL, ".github/workflows/ci.yml missing")
    required = ("ruff", "mypy", "bandit", "pytest")
    missing = [tool for tool in required if tool not in ci]
    if missing:
        return CheckResult(ControlStatus.FAIL, f"CI missing stages: {', '.join(missing)}")
    return CheckResult(ControlStatus.PASS, "CI runs ruff, mypy, bandit, and pytest")


def check_precommit_secret_scan(root: Path) -> CheckResult:
    """Pre-commit hooks include a secret scanner."""
    config = _read_text(root, ".pre-commit-config.yaml")
    if config is None:
        return CheckResult(ControlStatus.FAIL, ".pre-commit-config.yaml missing")
    if "detect-secrets" in config or "gitleaks" in config:
        return CheckResult(ControlStatus.PASS, "secret scanning wired into pre-commit")
    return CheckResult(ControlStatus.FAIL, "no secret-scan hook in pre-commit config")


def check_security_test_suite(root: Path) -> CheckResult:
    """A dedicated security test suite exists and is non-trivial."""
    tests_dir = _resolve_inside(root, "tests/security")
    if not tests_dir.is_dir():
        return CheckResult(ControlStatus.FAIL, "tests/security/ missing")
    modules = sorted(p.name for p in tests_dir.glob("test_*.py"))
    if len(modules) < 5:
        return CheckResult(ControlStatus.FAIL, f"only {len(modules)} security test module(s)")
    return CheckResult(ControlStatus.PASS, f"{len(modules)} security test modules")


def check_governance_docs(root: Path) -> CheckResult:
    """Charter, design, security policy, and contribution docs exist."""
    required = ("AGENTS.md", "DESIGN.md", "SECURITY.md", "CONTRIBUTING.md")
    missing = [
        name
        for name in required
        if not (
            _resolve_inside(root, name).is_file() and _resolve_inside(root, name).stat().st_size > 0
        )
    ]
    if missing:
        return CheckResult(ControlStatus.FAIL, f"missing or empty: {', '.join(missing)}")
    return CheckResult(ControlStatus.PASS, "all governance documents present")


def check_dashboard_upload_cap(root: Path) -> CheckResult:
    """The dashboard bounds upload size (denial-of-service hardening)."""
    config = _read_text(root, ".streamlit/config.toml")
    if config is None:
        return CheckResult(ControlStatus.FAIL, ".streamlit/config.toml missing")
    if re.search(r"maxUploadSize\s*=\s*\d+", config):
        return CheckResult(ControlStatus.PASS, "maxUploadSize configured for the dashboard")
    return CheckResult(ControlStatus.FAIL, "maxUploadSize not set in .streamlit/config.toml")


#: Addresses that keep the dashboard reachable only from the host it runs on.
#: Deliberately a small allow-list rather than a "not 0.0.0.0" check: the
#: interesting failure is a bind that is reachable, and enumerating the two
#: loopback forms is the honest way to say "only this host".
_LOOPBACK_ADDRESSES = ("127.0.0.1", "::1", "localhost")


def check_dashboard_binds_loopback(root: Path) -> CheckResult:
    """The dashboard binds only to loopback, so exposure is a deliberate act.

    The dashboard authenticates nobody and renders stored event content, so a
    bind address reachable from elsewhere publishes hostnames, accounts,
    addresses and raw log messages to whoever can reach the port. This was
    unset until it was pinned, which meant the address came from whatever the
    installed Streamlit defaulted to — not a property this repository
    controlled, while `docs/PRODUCTION_SOC_PLAN.md` described it as an
    invariant. Fails closed: an unreadable or absent config is a FAIL, and so
    is any address not on the loopback allow-list.
    """
    config = _read_text(root, ".streamlit/config.toml")
    if config is None:
        return CheckResult(ControlStatus.FAIL, ".streamlit/config.toml missing")
    match = re.search(r"^\s*address\s*=\s*[\"']([^\"']+)[\"']", config, re.MULTILINE)
    if match is None:
        return CheckResult(
            ControlStatus.FAIL,
            "server.address not set in .streamlit/config.toml; the bind address is "
            "then whatever the installed Streamlit defaults to",
        )
    address = match.group(1)
    if address not in _LOOPBACK_ADDRESSES:
        return CheckResult(
            ControlStatus.FAIL,
            f"dashboard binds {address!r}, which is not loopback; it authenticates "
            "nobody and renders stored event content",
        )
    return CheckResult(ControlStatus.PASS, f"dashboard binds loopback only ({address})")


# --- registry ---------------------------------------------------------------


def _refs(*pairs: tuple[Framework, str]) -> frozenset[FrameworkRef]:
    return frozenset(FrameworkRef(framework=fw, reference=ref) for fw, ref in pairs)


def registry() -> tuple[Control, ...]:
    """The full control catalog, ordered by id."""
    return (
        Control(
            id="POL-01",
            title="Policy engine denies boundary crossings by default",
            description=(
                "The policy layer refuses prohibited action classes and gates "
                "unknown actions instead of allowing them."
            ),
            category=Category.POLICY,
            severity=Severity.CRITICAL,
            framework_refs=_refs(
                (Framework.NIST_CSF, "GV.PO-01"),
                (Framework.SOC_2, "CC5.2"),
                (Framework.ISO_27001, "A.5.1"),
            ),
            check=check_policy_default_deny,
        ),
        Control(
            id="POL-02",
            title="Irreversible actions require human approval",
            description=(
                "Destructive, external-network, deployment, and secret-handling "
                "actions are gated behind explicit human approval."
            ),
            category=Category.POLICY,
            severity=Severity.CRITICAL,
            framework_refs=_refs(
                (Framework.NIST_CSF, "PR.AA-05"),
                (Framework.SOC_2, "CC6.3"),
                (Framework.ISO_27001, "A.8.2"),
            ),
            check=check_approval_gates,
        ),
        Control(
            id="AUD-01",
            title="Tamper-evident audit logging",
            description=(
                "Security-relevant decisions append to a hash-chained, "
                "verifiable audit log covered by security tests."
            ),
            category=Category.AUDIT,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "DE.CM-01"),
                (Framework.SOC_2, "CC7.2"),
                (Framework.ISO_27001, "A.8.15"),
            ),
            check=check_audit_logging_present,
        ),
        Control(
            id="AUD-02",
            title="The platform measures its own service level",
            description=(
                "Service-level objectives for collection, ingest freshness, "
                "detection lag, store readability, audit-chain integrity and "
                "recoverability are defined with recorded derivations, and an "
                "indicator that cannot be measured is not counted as healthy."
            ),
            category=Category.AUDIT,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "DE.CM-09"),
                (Framework.SOC_2, "CC7.2"),
                (Framework.ISO_27001, "A.8.16"),
            ),
            check=check_self_monitoring_defined,
        ),
        Control(
            id="AUD-03",
            title="Service-level objectives met on the deployed node",
            description=(
                "A human has run scripts/report_sli.py against the deployed "
                "lab root and either found every objective met or acted on "
                "what was not. Manual by necessity rather than by preference: "
                "the objectives measure a *running* platform — a collector "
                "keeping up, a store that is fresh and readable, a cycle that "
                "is not behind, chains that verify, a backup to restore from — "
                "and a repository checkout is not one, so an automated check "
                "here would be permanently red everywhere the control suite "
                "runs. A control that can never pass is a control people learn "
                "to ignore. The gate on the deployed node is the CLI's exit "
                "code, which is non-zero for any objective breached *or* "
                "unmeasurable; this expiring attestation is what stops a node "
                "nobody has looked at from silently claiming currency, which "
                "is the same argument MAN-03 makes for corpus freshness. What "
                "that exit code is *not* is a census of the evidence behind "
                "those objectives: an emptied store meets every one of them, "
                "measured, so the hint carries a withholding rule rather than "
                "resting on the code. Nothing enforces that rule — the note is "
                "free text and a current attestation is ATTESTED whatever it "
                "says — so the control is review of the committed "
                "attestations.json, and the rule is what a reviewer checks "
                "against."
            ),
            category=Category.AUDIT,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "DE.CM-09"),
                (Framework.SOC_2, "A1.1"),
                (Framework.ISO_27001, "A.8.6"),
            ),
            attestation_hint=(
                "On the deployed node: python scripts/report_sli.py --root "
                "<lab root> --json. Attest to the per-indicator verdicts, NOT "
                "to the exit code: every objective is met on a store pruned to "
                "zero rows, so the code cannot witness the evidence behind "
                "them. Read store-readable's detail and record its row counts "
                "in the note — it is the only reading that moves when the "
                "evidence does; detection-backlog does not move on a caught-up "
                "node. THEN DECIDE: if those counts are zero, or lower than "
                "the last attestation, DO NOT ATTEST until a retention pass in "
                "the audit chain and a backup manifest together account for "
                "the drop; record which accounted for it. Zero rows with every "
                "objective met is the state this control exists to catch. The "
                "grading itself is correct and deliberate — sli/indicators.py "
                "says why — so do not treat a quiet report as a broken "
                "indicator set."
            ),
        ),
        Control(
            id="SEC-01",
            title="No secrets in version control",
            description=(
                ".env files are gitignored and .env.example documents "
                "configuration keys without carrying values."
            ),
            category=Category.SECRETS,
            severity=Severity.CRITICAL,
            framework_refs=_refs(
                (Framework.NIST_CSF, "PR.AA-01"),
                (Framework.SOC_2, "CC6.1"),
                (Framework.ISO_27001, "A.5.33"),
            ),
            check=check_secret_hygiene,
        ),
        Control(
            id="SEC-02",
            title="Lab data isolated from version control",
            description="Local/lab data under data/ is excluded from the repository.",
            category=Category.SECRETS,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "PR.DS-01"),
                (Framework.SOC_2, "CC6.5"),
                (Framework.ISO_27001, "A.8.10"),
            ),
            check=check_lab_data_isolated,
        ),
        Control(
            id="SUP-01",
            title="Dependencies pinned via lockfile",
            description="All dependencies resolve from the committed uv.lock.",
            category=Category.SUPPLY_CHAIN,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "ID.RA-09"),
                (Framework.SOC_2, "CC8.1"),
                (Framework.ISO_27001, "A.8.9"),
            ),
            check=check_dependency_lock,
        ),
        Control(
            id="SUP-02",
            title="Software bill of materials published",
            description="CycloneDX SBOMs are generated and kept in security/sbom/.",
            category=Category.SUPPLY_CHAIN,
            severity=Severity.MEDIUM,
            framework_refs=_refs(
                (Framework.NIST_CSF, "ID.AM-02"),
                (Framework.SOC_2, "CC8.1"),
                (Framework.ISO_27001, "A.8.9"),
            ),
            check=check_sbom_present,
        ),
        Control(
            id="SUP-03",
            title="ATT&CK corpus pinned and integrity-verified",
            description=(
                "The committed local ATT&CK shards match the version pin's "
                "per-shard hashes and pass revocation/successor invariants."
            ),
            category=Category.SUPPLY_CHAIN,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "ID.RA-09"),
                (Framework.SOC_2, "CC8.1"),
                (Framework.ISO_27001, "A.8.9"),
            ),
            check=check_attack_corpus_integrity,
        ),
        Control(
            id="CIC-01",
            title="CI enforces quality and security gates",
            description="Every change passes lint, type, SAST, and test stages in CI.",
            category=Category.CI_CD,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "PR.PS-06"),
                (Framework.SOC_2, "CC8.1"),
                (Framework.ISO_27001, "A.8.29"),
            ),
            check=check_ci_gates,
        ),
        Control(
            id="CIC-02",
            title="Secret scanning before commit",
            description="Pre-commit hooks scan staged changes for credentials.",
            category=Category.CI_CD,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "PR.DS-05"),
                (Framework.SOC_2, "CC6.1"),
                (Framework.ISO_27001, "A.8.28"),
            ),
            check=check_precommit_secret_scan,
        ),
        Control(
            id="TST-01",
            title="Dedicated security test suite",
            description=(
                "Authorization, validation, injection, and secret-leak "
                "scenarios have dedicated tests that gate merges."
            ),
            category=Category.TESTING,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "ID.RA-01"),
                (Framework.SOC_2, "CC4.1"),
                (Framework.ISO_27001, "A.8.29"),
            ),
            check=check_security_test_suite,
        ),
        Control(
            id="DOC-01",
            title="Governance documentation maintained",
            description="Charter, design record, security policy, and contribution guide exist.",
            category=Category.POLICY,
            severity=Severity.MEDIUM,
            framework_refs=_refs(
                (Framework.NIST_CSF, "GV.PO-02"),
                (Framework.SOC_2, "CC1.4"),
                (Framework.ISO_27001, "A.5.1"),
            ),
            check=check_governance_docs,
        ),
        Control(
            id="CFG-01",
            title="Dashboard input limits configured",
            description="The Streamlit dashboard bounds upload sizes.",
            category=Category.CONFIGURATION,
            severity=Severity.LOW,
            framework_refs=_refs(
                (Framework.NIST_CSF, "PR.PS-01"),
                (Framework.SOC_2, "CC6.8"),
                (Framework.ISO_27001, "A.8.26"),
            ),
            check=check_dashboard_upload_cap,
        ),
        Control(
            id="CFG-02",
            title="Dashboard binds loopback only",
            description=(
                "The Streamlit dashboard binds 127.0.0.1. It authenticates no "
                "one and renders stored event content, so exposure must be a "
                "deliberate deployment act behind an authenticating proxy."
            ),
            category=Category.CONFIGURATION,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "PR.AA-05"),
                (Framework.SOC_2, "CC6.6"),
                (Framework.ISO_27001, "A.8.20"),
            ),
            check=check_dashboard_binds_loopback,
        ),
        Control(
            id="MAN-01",
            title="Branch protection on main",
            description=(
                "Branch rulesets on main block deletion and non-fast-forward "
                "(force) pushes with no bypass actor, and require the CI status "
                "checks before a ref update, waivable by a repository role "
                "holding an always-on bypass. Deliberately does NOT assert "
                "pull-request-only merges "
                "or review before merge: neither is enforced, and a solo "
                "maintainer cannot approve their own pull request. Verified in "
                "GitHub settings, not offline."
            ),
            category=Category.CI_CD,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "PR.AA-05"),
                (Framework.SOC_2, "CC8.1"),
                (Framework.ISO_27001, "A.8.32"),
            ),
            attestation_hint=(
                "GitHub -> Settings -> Rules: confirm main's rulesets carry "
                "deletion and non_fast_forward with an empty bypass_actors, "
                "and required_status_checks covering the CI contexts. The "
                "authoritative read is the API: "
                "repos/<owner>/<repo>/rules/branches/main."
            ),
        ),
        Control(
            id="MAN-02",
            title="Human approval gate on deployments",
            description=(
                "The github-pages environment requires manual approval before "
                "any deploy. Verified in GitHub settings, not offline."
            ),
            category=Category.CI_CD,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "PR.PS-06"),
                (Framework.SOC_2, "CC8.1"),
                (Framework.ISO_27001, "A.8.32"),
            ),
            attestation_hint=(
                "GitHub -> Settings -> Environments -> github-pages: confirm a "
                "required reviewer is configured."
            ),
        ),
        Control(
            id="MAN-03",
            title="ATT&CK corpus reviewed against the current upstream release",
            description=(
                "A human has compared the pinned ATT&CK version to the current "
                "MITRE release and either refreshed the corpus or accepted the "
                "distance. Freshness is advisory by design (never a build "
                "gate), so this expiring attestation is what keeps an "
                "unmaintained corpus from silently claiming currency."
            ),
            category=Category.SUPPLY_CHAIN,
            severity=Severity.MEDIUM,
            framework_refs=_refs(
                (Framework.NIST_CSF, "ID.RA-09"),
                (Framework.SOC_2, "CC8.1"),
                (Framework.ISO_27001, "A.8.9"),
            ),
            attestation_hint=(
                "Run scripts/update_attack.py --plan; refresh via --build or "
                "record acceptance of the reported version distance."
            ),
        ),
    )
