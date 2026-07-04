"""Declarative policy bundle loader — externalizes the §5/§5.1 policy (fail-closed).

The in-code default (:mod:`agents.policies.approval`) remains the safety net; this
module lets an operator ship the policy as a versioned, reviewable **JSON** document
instead of editing Python. JSON is deliberate — stdlib-only parsing, so this adds no
third-party runtime dependency (AGENTS.md §4).

Fails closed: a missing, unreadable, malformed, or schema-invalid bundle raises
:class:`PolicyBundleError`. The caller must not fall back to an implicit allow.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast, get_args

from agents.policies.approval import ActionClass, Decision, PolicyEngine

_VALID_CLASSES: frozenset[str] = frozenset(get_args(ActionClass))
_VALID_DECISIONS: frozenset[str] = frozenset(get_args(Decision))

#: The default bundle shipped alongside this module.
DEFAULT_BUNDLE_PATH = Path(__file__).with_name("policy.json")


class PolicyBundleError(ValueError):
    """Raised when a policy bundle is missing, unreadable, or schema-invalid."""


def load_bundle(path: Path | str = DEFAULT_BUNDLE_PATH) -> PolicyEngine:
    """Load a declarative JSON policy bundle into a :class:`PolicyEngine` (fail-closed).

    Expected schema::

        {
          "version": 1,
          "policy": { "<action_class>": "<decision>", ... },   # optional overrides
          "allow":  ["exact action label", ...],               # optional
          "deny":   ["exact action label", ...]                # optional
        }

    Raises:
        PolicyBundleError: on a missing file, invalid JSON, wrong types, or an
            unknown ``action_class`` / ``decision`` value. Never returns a
            partially-applied engine.
    """
    bundle_path = Path(path)
    try:
        raw = bundle_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyBundleError(f"policy bundle not readable: {bundle_path} ({exc})") from exc
    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyBundleError(f"policy bundle is not valid JSON: {bundle_path} ({exc})") from exc
    if not isinstance(data, dict):
        raise PolicyBundleError("policy bundle must be a JSON object")

    policy = _parse_policy(data.get("policy", {}))
    allow = _parse_str_list(data.get("allow", []), field="allow")
    deny = _parse_str_list(data.get("deny", []), field="deny")
    return PolicyEngine(policy=policy, allow=allow, deny=deny)


def _parse_policy(value: Any) -> dict[ActionClass, Decision]:
    if not isinstance(value, dict):
        raise PolicyBundleError("'policy' must be an object mapping action_class -> decision")
    result: dict[ActionClass, Decision] = {}
    for key, decision in value.items():
        if key not in _VALID_CLASSES:
            raise PolicyBundleError(f"unknown action_class in bundle: {key!r}")
        if decision not in _VALID_DECISIONS:
            raise PolicyBundleError(f"invalid decision for {key!r}: {decision!r}")
        result[cast(ActionClass, key)] = cast(Decision, decision)
    return result


def _parse_str_list(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyBundleError(f"'{field}' must be a list of strings")
    return list(value)
