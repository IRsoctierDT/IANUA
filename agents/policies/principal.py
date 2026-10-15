# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Who is asking — a caller identity that is safe to put in the audit chain.

Until now this platform had no caller identity at all. ``DESIGN.md``'s Decision
Log records that as one of three reasons the plan→execution boundary in
``agents/response/`` stays closed: *"AuditLogger.record has no structured
payload slot to bind an approval to; and the repository has no caller identity
at all."* This module supplies the second half.

**It rides in the existing ``actor`` field, deliberately.** ``actor`` is
already part of the audit hash preimage (``audit.py``'s ``"|".join`` over eight
fields), already a caller-supplied parameter at every enforcement site, and
already compounded by ``guarded.enforce`` (``f"{actor}[report-only]"``). So a
principal needs no new field, no record-schema version, and no migration —
which matters because ``AuditEvent(**json.loads(line))`` raises on a missing
*and* on an unexpected key, so a schema change breaks reading in both
directions, and that exception escapes through ``record()`` → ``enforce()`` →
every dispatch. Reusing a hashed field avoids all of it.

Security considerations (AGENTS.md §3, §5):

* **Attributable, because it is hashed.** A principal recorded outside the
  preimage — an unhashed JSON key, a side file — would be editable on disk
  without breaking the chain or the head signature. Riding in ``actor`` puts
  it inside the hash, which is the only place it means anything.
* **Cannot carry the field delimiter.** The preimage is an unescaped ``|``
  join, so a value containing ``|`` lets a writer forge a different field
  split: a deny record can be made to hash identically to an allow record.
  The alphabet below excludes ``|`` by construction, and
  ``audit.record`` rejects it as a backstop.
* **No ambient authority.** There is no ``principal_from_env``, no
  module-level default, and no ``field(default_factory=...)`` reading the
  process environment. A principal is constructed explicitly and passed
  explicitly. This is stated because the repository already contains that
  idiom four times over in ``agents/tools/llm.py``, and an ``IANUA_PRINCIPAL``
  environment key would read as idiomatic here while being an unauthenticated
  claim of identity.
* **Not authentication.** A ``Principal`` records *who the caller said they
  are*. Nothing here verifies it. That is honest and sufficient for
  attribution in a single-operator deployment; binding it to a verified
  credential is a later stage, and the docstring says so rather than letting
  a reader assume otherwise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: One part of a principal (the component, or the caller). Deliberately narrow:
#: alphanumeric plus ``. _ - @``, which covers service names, usernames, and
#: email/UPN forms without admitting the audit delimiter, whitespace, control
#: characters, or the ``/`` used to join the two parts.
#:
#: ``tests/security/test_principal.py`` asserts this alphabet excludes
#: ``audit``'s delimiter, so the two cannot drift apart.
_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")

#: Joins component and caller in the rendered form. Not in :data:`_PART`, so a
#: rendered principal always splits back into exactly two parts.
SEPARATOR = "/"

#: Longest part, taken from :data:`_PART` rather than restated: one leading
#: character plus 63 more.
MAX_PART = 64

#: Longest rendered principal. **Derived, not enforced at runtime:** two parts
#: at :data:`MAX_PART` joined by a one-character separator cannot exceed this,
#: so a runtime length check on the rendered form could never fire. The bound
#: is asserted in ``tests/security/test_principal.py`` instead, which is the
#: honest place for an arithmetic property — a guard that cannot trigger reads
#: like protection while providing none.
MAX_RENDERED = MAX_PART * 2 + len(SEPARATOR)


class PrincipalError(ValueError):
    """A principal is not in a shape that is safe to audit.

    Raised at construction rather than at write time. The audit record for a
    containment action is written *after* the effect, so a value rejected only
    at that point would mean the host action succeeded and the audit write
    failed. Validating when the principal is built moves the failure to
    startup, where it is harmless.
    """


@dataclass(frozen=True, slots=True)
class Principal:
    """A caller identity: which component, and on whose behalf.

    ``component`` is the part of the platform making the request
    (``containment``, ``mcp``, ``tool``) — what ``actor`` already carried.
    ``caller`` is who it is acting for, when that is known. Keeping both means
    adding identity does not lose the information the field held before.
    """

    component: str
    caller: str | None = None

    def __post_init__(self) -> None:
        """Validate both parts. The rendered length is bounded by construction."""
        if not _PART.fullmatch(self.component):
            raise PrincipalError(
                f"principal component must match {_PART.pattern!r}, got {self.component!r}"
            )
        if self.caller is not None and not _PART.fullmatch(self.caller):
            raise PrincipalError(
                f"principal caller must match {_PART.pattern!r}, got {self.caller!r}"
            )

    def render(self) -> str:
        """The audit-safe scalar form: ``component`` or ``component/caller``.

        A component with no caller renders exactly as the bare string the
        field carried before this type existed, so existing audit records and
        new ones remain directly comparable.
        """
        if self.caller is None:
            return self.component
        return f"{self.component}{SEPARATOR}{self.caller}"

    def __str__(self) -> str:
        return self.render()


def coerce(actor: Principal | str) -> str:
    """Render a principal, or pass through a legacy ``actor`` string.

    The enforcement sites accept either while callers migrate. A plain string
    is validated to the same alphabet as a principal part — except that the
    existing ``[report-only]`` marker ``guarded.enforce`` appends is tolerated,
    since that decoration predates this module and is not caller-supplied.
    """
    if isinstance(actor, Principal):
        return actor.render()
    bare = actor.removesuffix("[report-only]")
    head, _, tail = bare.partition(SEPARATOR)
    for part in (head, tail) if tail else (head,):
        if not _PART.fullmatch(part):
            raise PrincipalError(
                f"actor {actor!r} is not a valid principal; build a Principal instead"
            )
    return actor
