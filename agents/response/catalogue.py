"""Fail-closed loader for the committed response-action catalogue.

The catalogue is reviewed data, not code: actions land through PRs and are
validated whole-store in the ``compliance/attestations.py`` style. The
validation encodes the safety properties rather than trusting the author:

* every verb is on the closed :data:`RESTRICT_ONLY_VERBS` allow-list, so an
  action that *grants* access or acts on a third party cannot be expressed;
* every action names a human ``owner`` — no action may be owned by this
  platform;
* every action carries a ``rollback`` statement, including the irreversible
  ones, which must say plainly that they cannot be undone;
* any action that destroys or alters evidence must declare a prerequisite,
  so a plan can never order termination before memory capture.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.response.plan import RESTRICT_ONLY_VERBS, ResponseAction, sanitize_target

CATALOGUE_PATH = Path(__file__).resolve().parent / "actions.json"

_ACTION_FIELDS = {
    "action_id",
    "title",
    "tier",
    "verb",
    "action_class",
    "reversible",
    "destroys_evidence",
    "owner",
    "rationale",
    "steps",
    "rollback",
    "prerequisites",
}
_VALID_TIERS = {0, 2, 3}
_VALID_ACTION_CLASSES = {"read_only", "destructive", "secret_handling"}
_MAX_ACTIONS = 64
_MAX_STEPS = 12
_MAX_TEXT = 1000
_MAX_FILE_BYTES = 128 * 1024


class ResponseCatalogueError(ValueError):
    """Raised when the committed catalogue fails validation (whole-store)."""


def _reject(reason: str) -> ResponseCatalogueError:
    return ResponseCatalogueError(f"invalid response catalogue: {reason}")


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT:
        raise _reject(f"{context} must be a non-empty string of <= {_MAX_TEXT} chars")
    return value


def _text_list(value: object, context: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > _MAX_STEPS
        or (not value and not allow_empty)
        or not all(isinstance(item, str) and 0 < len(item) <= _MAX_TEXT for item in value)
    ):
        raise _reject(f"{context} must be a list of <= {_MAX_STEPS} bounded strings")
    return tuple(value)


def load_catalogue(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load and validate the catalogue; return it keyed by ``action_id``."""
    catalogue_path = CATALOGUE_PATH if path is None else path
    if not catalogue_path.is_file():
        raise _reject(f"catalogue not found: {catalogue_path}")
    raw = catalogue_path.read_bytes()
    if len(raw) > _MAX_FILE_BYTES:
        raise _reject(f"catalogue exceeds {_MAX_FILE_BYTES} bytes")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _reject(f"catalogue is not valid JSON ({exc})") from exc
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise _reject("catalogue must be an object with schema 1")
    actions = document.get("actions")
    if not isinstance(actions, list) or not actions or len(actions) > _MAX_ACTIONS:
        raise _reject(f"actions must be a list of 1..{_MAX_ACTIONS} entries")

    parsed: dict[str, dict[str, Any]] = {}
    for entry in actions:
        if not isinstance(entry, dict) or set(entry) != _ACTION_FIELDS:
            raise _reject(f"action must carry exactly {sorted(_ACTION_FIELDS)}")
        action_id = _text(entry["action_id"], "action_id")
        if action_id in parsed:
            raise _reject(f"duplicate action_id {action_id!r}")
        context = f"action {action_id!r}"

        verb = entry["verb"]
        if verb not in RESTRICT_ONLY_VERBS:
            raise _reject(
                f"{context}: verb {verb!r} is not on the restrict-only allow-list "
                f"{sorted(RESTRICT_ONLY_VERBS)} — this schema cannot express an action "
                "that grants access or acts on a third party"
            )
        if entry["tier"] not in _VALID_TIERS:
            raise _reject(f"{context}: tier must be one of {sorted(_VALID_TIERS)}")
        if entry["action_class"] not in _VALID_ACTION_CLASSES:
            raise _reject(f"{context}: unknown action_class {entry['action_class']!r}")

        owner = _text(entry["owner"], f"{context} owner")
        if "ianua" in owner.lower() or "agent" in owner.lower():
            raise _reject(
                f"{context}: owner {owner!r} names this platform — every response action "
                "is performed by a human operator (DESIGN.md §5 boundary 8)"
            )

        for flag in ("reversible", "destroys_evidence"):
            if not isinstance(entry[flag], bool):
                raise _reject(f"{context}: {flag} must be a boolean")

        rollback = _text(entry["rollback"], f"{context} rollback")
        if not entry["reversible"] and "not reversible" not in rollback.lower():
            raise _reject(
                f"{context}: an irreversible action's rollback must say plainly that it "
                "cannot be undone"
            )

        prerequisites = _text_list(
            entry["prerequisites"], f"{context} prerequisites", allow_empty=True
        )
        if entry["destroys_evidence"] and not prerequisites:
            raise _reject(
                f"{context}: an evidence-affecting action must declare a prerequisite so "
                "capture is ordered before disruption"
            )

        parsed[action_id] = {
            "action_id": action_id,
            "title": _text(entry["title"], f"{context} title"),
            "tier": entry["tier"],
            "verb": verb,
            "action_class": entry["action_class"],
            "owner": owner,
            "rationale": _text(entry["rationale"], f"{context} rationale"),
            "steps": _text_list(entry["steps"], f"{context} steps"),
            "rollback": rollback,
            "reversible": entry["reversible"],
            "destroys_evidence": entry["destroys_evidence"],
            "prerequisites": prerequisites,
        }

    for action_id, action in parsed.items():
        for prerequisite in action["prerequisites"]:
            if prerequisite not in parsed:
                raise _reject(
                    f"action {action_id!r}: prerequisite {prerequisite!r} is not in the catalogue"
                )
            if prerequisite == action_id:
                raise _reject(f"action {action_id!r}: prerequisite refers to itself")
    return parsed


def build_action(
    action_id: str, target: str, catalogue: dict[str, dict[str, Any]]
) -> ResponseAction:
    """Bind a catalogue action to a sanitized target."""
    entry = catalogue.get(action_id)
    if entry is None:
        raise _reject(f"unknown action_id {action_id!r}")
    return ResponseAction(
        action_id=entry["action_id"],
        title=entry["title"],
        tier=entry["tier"],
        verb=entry["verb"],
        action_class=entry["action_class"],
        target=sanitize_target(target),
        owner=entry["owner"],
        rationale=entry["rationale"],
        steps=entry["steps"],
        rollback=entry["rollback"],
        reversible=entry["reversible"],
        destroys_evidence=entry["destroys_evidence"],
        prerequisites=entry["prerequisites"],
    )
