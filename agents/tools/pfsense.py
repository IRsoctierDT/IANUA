# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""pfSense containment adapter — stage 8, phase 2: **dry run only**.

Turns one :class:`~agents.policies.execution_approval.VerifiedApproval` into the
exact pfREST v2 requests that would block, unblock, isolate or restore one
address on the lab firewall, records them to the audit chain, and **sends
nothing**. This module has no transport: it imports no socket, HTTP, TLS or
subprocess module (asserted over its AST by
``tests/security/test_pfsense_adapter.py``), so there is no flag, environment
key or argument that makes it reach a network. Phase 3 adds a transport under
its own ``AGENTS.md`` §5 amendment.

**The model, and why aliases.** Every action edits the address list of one of
two operator-created pfSense *host aliases* — :data:`DEFAULT_BLOCK_ALIAS` and
:data:`DEFAULT_ISOLATE_ALIAS` — which the operator references from block rules
they wrote and reviewed on the firewall. IANUA therefore never creates, edits or
deletes a firewall *rule*: the blast radius of a mistaken action is one address
added to, or removed from, a list a human already decided to block. Rollback is
the inverse capability, which needs its own signed approval.

**The request shapes**, from the pfREST package documentation and its
maintainer's guidance (not yet exercised against a live device — that is a
phase 3 obligation, against the device's own ``/api/v2/documentation``):

* ``GET /api/v2/firewall/aliases?name=<alias>`` to resolve the alias's ``id``,
  because pfREST addresses an alias by an index that changes when aliases are
  deleted, so it cannot be configured statically.
* ``PATCH /api/v2/firewall/alias`` with ``{"id", "address": [<target>],
  "append" | "remove": true, "apply": true}``. ``append``/``remove`` edit the
  array server-side, so there is no read-modify-write of the whole list here
  and no window in which a concurrent edit is overwritten; ``apply`` commits
  the change in the same request.

Security considerations (AGENTS.md §3, §5):

* **The approval is the only input.** :meth:`PfSenseDryRun.dry_run` takes a
  ``VerifiedApproval`` and nothing else that names an action or a target, so
  the request cannot describe anything other than what was signed. That is the
  phase 1 residual ("the gate cannot verify that the caller then does what it
  described") closed for this adapter by construction rather than by a check.
* **IP literals only, canonical form only.** A target is parsed by
  :func:`agents.policies.egress.parse_address`, which refuses hostnames,
  integers, unspecified, multicast, broadcast, link-local, IPv4-mapped and
  scoped forms — measured refusals, reused rather than retyped. Loopback is
  refused here too, since a firewall alias entry for it means nothing. And the
  approval's string must *be* the canonical spelling: ``2001:DB8::1`` is
  refused in favour of ``2001:db8::1``, so one address cannot be approved
  twice under two spellings or audited under a spelling the firewall
  normalises differently.
* **No networks.** A single address per approval. Blocking a prefix is a
  larger blast radius than anything licensed so far and is not offered.
* **Protected addresses cannot be blocked or isolated** — the firewall's own
  management address, the operator's workstation, the IANUA node. Removing a
  protected address from an alias is still allowed, because that is recovery.
* **Once per approval, and only while it is fresh.** A ``VerifiedApproval`` used
  twice in one adapter is refused, and so is one past its expiry: the ledger
  consumed it at authorization, and this is a second layer, not the first.
* **Both outcomes audited**, with the approval digest and a digest of the exact
  change, so the record binds what was signed to what would have been sent.
* **Unsupported capabilities fail closed.** ``disable_account`` and
  ``enable_account`` are approvable but are not firewall actions; asking this
  adapter for one raises rather than doing something nearby.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agents.policies.audit import AuditLogger, escape_delimiter
from agents.policies.egress import EgressAllowlistError, parse_address
from agents.policies.execution_approval import VerifiedApproval

#: Operator-created alias holding addresses to drop at the edge.
DEFAULT_BLOCK_ALIAS = "IANUA_BLOCK"
#: Operator-created alias holding hosts cut off from everything but management.
DEFAULT_ISOLATE_ALIAS = "IANUA_ISOLATE"

ALIASES_PATH = "/api/v2/firewall/aliases"
ALIAS_PATH = "/api/v2/firewall/alias"

#: pfSense alias names: a letter, then letters, digits and underscores, at most
#: 31 characters. Narrower than pfSense allows on purpose — no leading digit or
#: underscore — so a name is never mistaken for an address or a macro.
_ALIAS_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,30}$")

#: capability → (which alias, which array operation)
_OPERATIONS: dict[str, tuple[str, str]] = {
    "block_indicator": ("block", "append"),
    "unblock_indicator": ("block", "remove"),
    "isolate_host": ("isolate", "append"),
    "restore_host": ("isolate", "remove"),
}

#: Capabilities this adapter can express. The rest of the approvable set is not
#: a firewall action and is refused.
SUPPORTED = frozenset(_OPERATIONS)

_Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class PfSenseError(ValueError):
    """Raised when an approved action cannot be expressed safely (fail closed)."""


def _parse_target(value: str) -> _Address:
    """Parse a target as a canonical, single-host, non-loopback IP literal."""
    try:
        address = parse_address(value)
    except EgressAllowlistError as exc:
        raise PfSenseError(f"target is not an acceptable IP literal: {exc}") from exc
    if address.is_loopback:
        raise PfSenseError(f"target {value!r} is loopback, which a firewall alias cannot mean")
    if str(address) != value:
        raise PfSenseError(
            f"target {value!r} is not in canonical form; approve {str(address)!r} instead"
        )
    return address


@dataclass(frozen=True, slots=True)
class PfSenseConfig:
    """Which aliases to edit and which addresses must never be blocked.

    ``protected`` holds canonical IP literals — the firewall's management
    address at minimum. Validated on construction; an invalid entry raises.
    """

    block_alias: str = DEFAULT_BLOCK_ALIAS
    isolate_alias: str = DEFAULT_ISOLATE_ALIAS
    protected: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        """Validate alias names, require them distinct, and parse every protected entry."""
        for name in (self.block_alias, self.isolate_alias):
            if type(name) is not str or not _ALIAS_NAME.fullmatch(name):
                raise PfSenseError(f"alias name {name!r} must match {_ALIAS_NAME.pattern}")
        if self.block_alias == self.isolate_alias:
            raise PfSenseError("block and isolate aliases must be different aliases")
        if not isinstance(self.protected, frozenset):
            raise PfSenseError("protected must be a frozenset of IP literals")
        for entry in self.protected:
            _parse_target(entry)

    def alias_for(self, role: str) -> str:
        """The alias name for ``role`` (``block`` or ``isolate``)."""
        return self.block_alias if role == "block" else self.isolate_alias


@dataclass(frozen=True, slots=True)
class PreparedRequest:
    """One HTTP request, fully specified except where ``id`` must be resolved."""

    method: str
    path: str
    query: tuple[tuple[str, str], ...] = ()
    body: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        """JSON-ready form, used for rendering and for the change digest."""
        return {
            "method": self.method,
            "path": self.path,
            "query": list(self.query),
            "body": self.body,
        }


@dataclass(frozen=True, slots=True)
class PreparedChange:
    """What phase 3 would send for one approval, and the condition it must check first.

    ``precondition`` is the check a live transport owes before the change
    request: the lookup must return exactly one alias with exactly this name and
    type ``host``, and its ``id`` is substituted for ``None``. Anything else —
    zero matches, two, a different type — refuses.
    """

    capability: str
    target: str
    alias: str
    operation: str
    approval_digest: str
    lookup: PreparedRequest
    change: PreparedRequest
    precondition: str

    def as_dict(self) -> dict[str, Any]:
        """JSON-ready form of the whole change."""
        return {
            "capability": self.capability,
            "target": self.target,
            "alias": self.alias,
            "operation": self.operation,
            "approval_digest": self.approval_digest,
            "lookup": self.lookup.as_dict(),
            "change": self.change.as_dict(),
            "precondition": self.precondition,
        }

    @property
    def digest(self) -> str:
        """sha256 over the canonical JSON of the change — what the audit record binds."""
        canonical = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()


class PfSenseDryRun:
    """Prepare and audit pfSense changes from verified approvals; never send one.

    ``clock`` is injectable for tests and defaults to :func:`time.time`.
    """

    def __init__(
        self,
        config: PfSenseConfig | None = None,
        *,
        audit: AuditLogger | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config if config is not None else PfSenseConfig()
        self.audit = audit
        self._clock = clock
        self._used: set[str] = set()

    def prepare(self, approval: VerifiedApproval) -> PreparedChange:
        """Build the change for ``approval`` without auditing or consuming it.

        Pure: the same approval and config always produce the same change.
        """
        if type(approval) is not VerifiedApproval:
            raise PfSenseError("a VerifiedApproval from execution_approval.authorize is required")
        operation = _OPERATIONS.get(approval.capability)
        if operation is None:
            raise PfSenseError(f"{approval.capability!r} is not a pfSense action")
        role, array_op = operation
        _parse_target(approval.target)
        alias = self.config.alias_for(role)
        if array_op == "append" and approval.target in self.config.protected:
            raise PfSenseError(f"{approval.target} is protected and cannot be added to {alias}")
        lookup = PreparedRequest(method="GET", path=ALIASES_PATH, query=(("name", alias),))
        change = PreparedRequest(
            method="PATCH",
            path=ALIAS_PATH,
            body={"id": None, "address": [approval.target], array_op: True, "apply": True},
        )
        return PreparedChange(
            capability=approval.capability,
            target=approval.target,
            alias=alias,
            operation=array_op,
            approval_digest=approval.digest,
            lookup=lookup,
            change=change,
            precondition=(
                f"lookup returns exactly one alias named {alias!r} of type 'host'; "
                "substitute its id for null, else refuse"
            ),
        )

    def dry_run(self, approval: VerifiedApproval) -> PreparedChange:
        """Prepare, audit and return the change for ``approval``. Sends nothing.

        Raises :class:`PfSenseError` — and records the refusal — when the
        approval was already used here, has expired, or names something this
        adapter cannot express safely.
        """
        try:
            if type(approval) is not VerifiedApproval:
                raise PfSenseError(
                    "a VerifiedApproval from execution_approval.authorize is required"
                )
            if approval.digest in self._used:
                raise PfSenseError("this approval has already been used by this adapter")
            if self._clock() >= approval.expires_at:
                raise PfSenseError("approval expired before the change was prepared")
            change = self.prepare(approval)
        except PfSenseError as exc:
            self._record(approval, decision="deny", reason=str(exc))
            raise
        self._used.add(approval.digest)
        self._record(
            approval,
            decision="dry-run",
            reason=(
                f"approval {change.approval_digest} change {change.digest} "
                f"{change.change.method} {change.change.path} "
                f"alias {change.alias} {change.operation}; not sent"
            ),
        )
        return change

    def _record(self, approval: object, *, decision: str, reason: str) -> None:
        """Append one audit record. Never raises on hostile input, so it cannot mask a refusal.

        The actor carries the approver only for a genuine ``VerifiedApproval``,
        whose approver id was validated against the registry alphabet; anything
        else is attributed to the bare component, because an identity field is
        never escaped (``audit.escape_delimiter``) and so must never be
        caller-shaped.
        """
        if self.audit is None:
            return
        if type(approval) is VerifiedApproval:
            actor = f"pfsense/{approval.approver}"
            summary = f"{approval.capability} {approval.target}"
        else:
            actor = "pfsense"
            summary = f"not-an-approval {type(approval).__name__}"
        self.audit.record(
            actor=actor,
            action=escape_delimiter(summary[:256]),
            action_class="containment",
            decision=decision,
            reason=escape_delimiter(reason[:512]),
        )
