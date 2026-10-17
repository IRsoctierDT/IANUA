# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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

#: The schema version this loader understands. A bundle naming another version is
#: refused rather than read under these semantics, the same rule ``egress.py``
#: applies to its allow-list. ``version`` stays optional (every field has a
#: fail-closed default, so ``{}`` is a valid bundle meaning "defaults") but when
#: present it must be exactly this integer.
SUPPORTED_VERSION = 1

#: Every key the schema below defines. Anything else is refused, not ignored.
_TOP_LEVEL_KEYS = frozenset({"version", "policy", "allow", "deny"})


class PolicyBundleError(ValueError):
    """Raised when a policy bundle is missing, unreadable, or schema-invalid."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``json.loads`` hook refusing a repeated key instead of silently keeping the last.

    The bundle is the standing-grant mechanism (``run_retention.py --apply`` passes
    only because a label is in ``allow``), and its whole claim is that a reviewer
    sees the grant in a diff. Measured on the loader without this hook:
    ``{"allow": [], "allow": ["retain_events:apply"]}`` loaded and *enforced* the
    grant while the first ``allow`` key — the one a reader's eye lands on — is
    empty; and ``{"deny": ["x"], "deny": []}`` dropped the deny-list the file
    visibly declares. ``egress.py`` already refuses this for the same reason.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise PolicyBundleError(
                f"duplicate key {key!r} in policy bundle: JSON keeps the last value "
                "silently, so the file would read one way and enforce another"
            )
        seen.add(key)
    return dict(pairs)


def load_bundle(path: Path | str = DEFAULT_BUNDLE_PATH) -> PolicyEngine:
    """Load a declarative JSON policy bundle into a :class:`PolicyEngine` (fail-closed).

    Expected schema::

        {
          "version": 1,                                         # optional; 1 if present
          "policy": { "<action_class>": "<decision>", ... },   # optional overrides
          "allow":  ["exact action label", ...],               # optional
          "deny":   ["exact action label", ...]                # optional
        }

    Raises:
        PolicyBundleError: on a missing file, invalid JSON, a duplicated key, an
            unknown top-level key, an unsupported ``version``, wrong types, or an
            unknown ``action_class`` / ``decision`` value. Never returns a
            partially-applied engine.

    An unknown top-level key is refused rather than skipped because the likeliest
    unknown key is a misspelled known one, and the two misspellings matter in
    opposite ways: measured, ``{"deni": ["analyze the log"]}`` loaded and the
    label stayed *allowed* — a deny-list the operator believes is in force and is
    not — while ``{"polcy": {...}}`` silently fell back to the defaults.
    """
    bundle_path = Path(path)
    try:
        raw = bundle_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyBundleError(f"policy bundle not readable: {bundle_path} ({exc})") from exc
    try:
        data: Any = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise PolicyBundleError(f"policy bundle is not valid JSON: {bundle_path} ({exc})") from exc
    if not isinstance(data, dict):
        raise PolicyBundleError("policy bundle must be a JSON object")
    unknown = sorted(set(data) - _TOP_LEVEL_KEYS)
    if unknown:
        raise PolicyBundleError(
            f"policy bundle has unknown keys: {unknown} — refused rather than ignored, "
            "because a misspelled 'deny' would leave a label allowed while looking denied"
        )
    if "version" in data:
        version = data["version"]
        # ``bool`` is an ``int`` subclass, so without the guard ``true == 1``
        # passes as schema version 1 (measured; ``egress.py`` records the same).
        if isinstance(version, bool) or not isinstance(version, int):
            raise PolicyBundleError(
                f"policy bundle version must be an integer, not "
                f"{type(version).__name__}: {version!r}"
            )
        if version != SUPPORTED_VERSION:
            raise PolicyBundleError(
                f"unsupported policy bundle version {version!r} "
                f"(this loader understands {SUPPORTED_VERSION})"
            )

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
        if key == "boundary_crossing" and decision != "deny":
            # The engine refuses this too; raising here keeps the error type a
            # bundle caller already handles, and names the file rather than
            # the object. A reader of the JSON would otherwise see permission
            # the engine never grants (AGENTS.md §5: non-negotiable).
            raise PolicyBundleError(
                f"'boundary_crossing' is an AGENTS.md §5 prohibition and must be "
                f"'deny', not {decision!r}: the engine denies it before reading this "
                "table, so any other value would be stored and never enforced"
            )
        result[cast(ActionClass, key)] = cast(Decision, decision)
    return result


def _parse_str_list(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyBundleError(f"'{field}' must be a list of strings")
    return list(value)
