"""Input-validation helpers for agent tool surfaces.

Every tool adapter MUST validate untrusted input (incl. LLM-generated strings)
before it reaches a filesystem path, shell, or query. See DESIGN.md §5 and
AGENTS.md §6.1 (review priorities #4-#5).
"""

from __future__ import annotations

from pathlib import Path


class ValidationError(ValueError):
    """Raised when untrusted input fails a security/validation check."""


def resolve_within(base: Path, candidate: str) -> Path:
    """Resolve ``candidate`` and guarantee it stays inside ``base``.

    Defends against path-traversal (``../``) from untrusted input.

    Args:
        base: Trusted root directory the result must remain within.
        candidate: Untrusted, caller-supplied relative path.

    Returns:
        The resolved absolute path, guaranteed to be inside ``base``.

    Raises:
        ValidationError: If the resolved path escapes ``base``.
    """
    base_resolved = base.resolve()
    target = (base_resolved / candidate).resolve()
    if base_resolved != target and base_resolved not in target.parents:
        raise ValidationError(f"path escapes allowed root: {candidate!r}")
    return target
