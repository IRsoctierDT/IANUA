"""Input-validation helpers for agent tool surfaces.

Every tool adapter MUST validate untrusted input (incl. LLM-generated strings)
before it reaches a filesystem path, shell, or query. See DESIGN.md §5 and
AGENTS.md §6.1 (review priorities #4-#5).
"""

from __future__ import annotations

from pathlib import Path

#: Upper bound on an untrusted path candidate (defends against oversized input).
_MAX_CANDIDATE_LEN = 4096


class ValidationError(ValueError):
    """Raised when untrusted input fails a security/validation check."""


def resolve_within(base: Path, candidate: str) -> Path:
    """Resolve ``candidate`` and guarantee it stays inside ``base``.

    Defends against path-traversal (``../``) from untrusted input, and rejects two
    classes of hostile input up front so they surface as :class:`ValidationError`
    rather than a lower-level ``ValueError``/``OSError``: embedded NUL bytes and
    oversized candidates.

    Args:
        base: Trusted root directory the result must remain within.
        candidate: Untrusted, caller-supplied relative path.

    Returns:
        The resolved absolute path, guaranteed to be inside ``base``.

    Raises:
        ValidationError: If the candidate contains a NUL byte, exceeds the length
            limit, or resolves to a path that escapes ``base``.
    """
    if "\x00" in candidate:
        raise ValidationError("path contains a NUL byte")
    if len(candidate) > _MAX_CANDIDATE_LEN:
        raise ValidationError(f"path exceeds {_MAX_CANDIDATE_LEN}-character limit")
    base_resolved = base.resolve()
    target = (base_resolved / candidate).resolve()
    if base_resolved != target and base_resolved not in target.parents:
        raise ValidationError(f"path escapes allowed root: {candidate!r}")
    return target
