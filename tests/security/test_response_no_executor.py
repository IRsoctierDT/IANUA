"""The containment boundary is closed by construction (DESIGN.md §5 boundary 8).

These tests are the enforcement behind the claim "IANUA does not execute
containment actions". They fail the build if executor code, an arming flag,
or a path from a plan to a host ever appears in ``agents/response/`` — which
is what makes the plan-only decision a control rather than a promise.

The boundary stays closed for reasons this repository can point at, not
squeamishness: the sandbox cannot perform host actions without weakening an
existing control, the policy allow-list is a standing grant rather than
per-invocation approval, the audit record has no payload slot to bind an
approval to, and there is no caller identity anywhere. Opening it requires
designing an explicit, signed, expiring, per-target approval primitive first.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest
from agents.response import RESTRICT_ONLY_VERBS, ResponsePlanner, load_catalogue

_RESPONSE_DIR = Path(__file__).resolve().parents[2] / "agents" / "response"

#: Modules that could reach a host, a process, or the network. None of them
#: may appear anywhere in the response package, directly or transitively.
_BANNED_MODULES = {
    "subprocess",
    "os",
    "shutil",
    "signal",
    "socket",
    "urllib",
    "http",
    "ssl",
    "ftplib",
    "smtplib",
    "asyncio",
    "multiprocessing",
    "ctypes",
    "paramiko",
    "docker",
    "mcp",
}

#: Dynamic-execution escape hatches an AST import walk would otherwise miss,
#: as bare names (``exec(...)``).
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "system", "popen", "spawn"}

#: The subset that is still dangerous as an *attribute* call (``os.system(...)``).
#: ``compile`` is excluded deliberately: ``re.compile`` is ordinary regex work,
#: and banning it here would flag benign code while catching nothing real —
#: the bare-name check above still covers the ``compile()`` builtin.
_BANNED_ATTR_CALLS = {"eval", "exec", "system", "popen", "spawn"}

#: Names that would indicate an executor had been introduced.
_EXECUTOR_MARKERS = (
    "def execute",
    "def run_action",
    "def apply_plan",
    "def arm",
    "RESPONSE_ENABLED",
    "ALLOW_EXECUTION",
    'execution_state = "approved"',
    'execution_state = "executed"',
)


def _modules() -> list[Path]:
    files = sorted(_RESPONSE_DIR.glob("*.py"))
    assert files, "agents/response/ has no modules?"
    return files


@pytest.mark.security
def test_no_executor_module_exists() -> None:
    """The package contains planning code only — no executor, by name or shape."""
    allowed = {"__init__.py", "plan.py", "catalogue.py", "planner.py"}
    present = {path.name for path in _modules()}
    unexpected = present - allowed
    assert not unexpected, (
        f"unexpected module(s) in agents/response/: {sorted(unexpected)} — adding an "
        "executor requires designing an approval primitive first (DESIGN.md §5 boundary 8)"
    )


@pytest.mark.security
def test_no_executor_markers_in_source() -> None:
    for path in _modules():
        source = path.read_text(encoding="utf-8")
        for marker in _EXECUTOR_MARKERS:
            assert marker not in source, f"{path.name}: executor marker {marker!r} present"


@pytest.mark.security
def test_no_import_path_to_host_process_or_network() -> None:
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in _BANNED_MODULES, f"{path.name} imports {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                assert root not in _BANNED_MODULES, f"{path.name} imports from {node.module}"
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _BANNED_CALLS, (
                    f"{path.name} calls {node.func.id} — dynamic-execution escape hatch"
                )
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in _BANNED_ATTR_CALLS, (
                    f"{path.name} calls .{node.func.attr}()"
                )


@pytest.mark.security
def test_transitive_import_surface_is_clean() -> None:
    """A fresh interpreter importing the package must not pull in an exec path."""
    # Baseline on the parent package first: `agents/__init__` resolves the
    # platform version through importlib.metadata, which drags in stdlib
    # email/socket machinery. That surface belongs to the package as a whole,
    # not to this layer — so the assertion is scoped to what importing
    # `agents.response` adds ON TOP of it, which must be nothing.
    code = (
        "import sys, agents; before = set(sys.modules); "
        "from agents.response import ResponsePlanner; ResponsePlanner(); "
        "new = set(sys.modules) - before; "
        "banned = {'subprocess', 'socket', 'ssl', 'ctypes', 'multiprocessing'}; "
        "hit = sorted(banned & new); print(','.join(hit) if hit else 'CLEAN')"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
        cwd=_RESPONSE_DIR.parents[1],
    )
    assert result.stdout.strip() == "CLEAN", f"response import pulled in: {result.stdout}"


@pytest.mark.security
def test_every_plan_is_draft_and_never_advances() -> None:
    planner = ResponsePlanner()
    plan = planner.plan_for_techniques(["T1110", "T1059.004"], ["web-01"])
    assert plan.execution_state == "draft"
    assert plan.to_dict()["execution_state"] == "draft"
    # Frozen dataclass: a caller cannot flip the state on an existing plan.
    # The attribute name is held in a variable deliberately — a literal
    # assignment is a static type error (the field is Literal["draft"]), and a
    # constant setattr trips ruff B010; this exercises the *runtime*
    # immutability guarantee, which is what actually protects the boundary.
    for field, value in {"execution_state": "executed"}.items():
        with pytest.raises((AttributeError, TypeError)):
            setattr(plan, field, value)


@pytest.mark.security
def test_every_action_is_owned_by_a_human() -> None:
    catalogue = load_catalogue()
    for action_id, action in catalogue.items():
        owner = action["owner"].lower()
        assert "ianua" not in owner and "agent" not in owner, (
            f"{action_id}: owner {action['owner']!r} names the platform"
        )
        assert action["owner"], f"{action_id}: no owner"


@pytest.mark.security
def test_catalogue_verbs_are_restrict_only() -> None:
    """The schema cannot express an action that grants access or hits a third party."""
    catalogue = load_catalogue()
    for action_id, action in catalogue.items():
        assert action["verb"] in RESTRICT_ONLY_VERBS, f"{action_id}: verb outside allow-list"
    forbidden = {"exploit", "scan", "install", "grant", "escalate", "pivot", "exfiltrate"}
    assert not (RESTRICT_ONLY_VERBS & forbidden), "allow-list admits an offensive verb"


@pytest.mark.security
def test_evidence_capture_precedes_every_destructive_step() -> None:
    """A plan may never order disruption before the evidence it would destroy."""
    planner = ResponsePlanner()
    plan = planner.plan_for_techniques(
        ["T1110", "T1059.004", "T1105", "T1685"], ["web-01", "203.0.113.5"]
    )
    tiers = [action.tier for action in plan.actions]
    assert tiers == sorted(tiers), "actions must be ordered collect -> reversible -> irreversible"
    first_destructive = next((i for i, a in enumerate(plan.actions) if a.destroys_evidence), None)
    if first_destructive is not None:
        earlier = plan.actions[:first_destructive]
        assert any(a.action_id == "capture-volatile-memory" for a in earlier), (
            "an evidence-destroying step appears before memory capture"
        )


@pytest.mark.security
def test_irreversible_actions_declare_their_finality() -> None:
    catalogue = load_catalogue()
    for action_id, action in catalogue.items():
        if not action["reversible"]:
            assert "not reversible" in action["rollback"].lower(), (
                f"{action_id}: irreversible action must say so in its rollback"
            )


@pytest.mark.security
def test_catalogue_is_committed_data_with_no_programmatic_writer() -> None:
    """Nothing in the package writes the catalogue — it changes via reviewed PR."""
    for path in _modules():
        source = path.read_text(encoding="utf-8")
        for writer in ("write_text(", "write_bytes(", "open(", "json.dump("):
            assert writer not in source, f"{path.name}: contains a writer ({writer})"


@pytest.mark.security
def test_plan_ids_are_deterministic_not_clock_derived() -> None:
    planner = ResponsePlanner()
    first = planner.plan_for_techniques(["T1110"], ["web-01"])
    second = planner.plan_for_techniques(["T1110"], ["web-01"])
    assert first.plan_id == second.plan_id
    assert first.to_dict() == second.to_dict()
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in ("now", "today", "utcnow"):
                raise AssertionError(f"{path.name} reads a clock ({node.attr})")


@pytest.mark.security
def test_committed_catalogue_round_trips() -> None:
    raw = json.loads((_RESPONSE_DIR / "actions.json").read_text(encoding="utf-8"))
    assert raw["schema"] == 1
    assert len(load_catalogue()) == len(raw["actions"])
