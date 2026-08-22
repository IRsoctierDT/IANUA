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


def check_attack_corpus_integrity(root: Path) -> CheckResult:
    """SUP-03: committed ATT&CK shards verify against the pin, offline.

    Read-only and fail closed: a missing pin, a hash mismatch, or a corpus
    that does not load is a FAIL — never a silent pass. Runs the same loader
    the platform uses, so the control is load-bearing, not decorative.
    """
    import sys

    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        from attack import load_corpus, load_pin

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
            id="MAN-01",
            title="Branch protection on main",
            description=(
                "No direct commits to main; required status checks and review "
                "before merge. Verified in GitHub settings, not offline."
            ),
            category=Category.CI_CD,
            severity=Severity.HIGH,
            framework_refs=_refs(
                (Framework.NIST_CSF, "PR.AA-05"),
                (Framework.SOC_2, "CC8.1"),
                (Framework.ISO_27001, "A.8.32"),
            ),
            attestation_hint=(
                "GitHub -> Settings -> Branches: confirm main requires PRs, "
                "status checks, and at least one review."
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
