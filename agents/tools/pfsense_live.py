# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""pfSense containment transport — stage 8, phase 3: **live**.

Sends the change :mod:`agents.tools.pfsense` prepares, to one declared lab
firewall, over TLS pinned to that firewall's certificate. It is the first code
in this repository that changes state on another host, so every control below
must pass before a byte of the change is written, and any one failing refuses.

The order of checks for :meth:`PfSenseLive.send`, each fail-closed:

1. **Standing grant.** ``guarded.enforce`` with action class
   ``external_network`` and label :data:`SEND_LABEL`. The shipped policy answers
   ``require_approval`` for that class, so this refuses until an operator adds
   ``pfsense:send`` to the ``allow`` list of their committed policy bundle —
   the ``run_retention.py --apply`` shape, reviewable in a diff.
2. **Declared destination.** The firewall's address and port must be declared
   in the egress allow-list (by owner decision, the gitignored
   ``data/egress.local.json``, because §5 treats internal addresses as sensitive
   and this repository is public) **and** in ``data/pfsense.local.json``.
   Neither file alone is sufficient.
3. **Signed approval.** A :class:`VerifiedApproval`, used once here and still
   unexpired; the request is derived from it by
   :meth:`agents.tools.pfsense.PfSenseDryRun.prepare`, so it cannot name
   anything that was not signed.
4. **API key present** in :data:`PFSENSE_KEY_ENV`, checked before any connection.
5. **Pinned certificate.** The TLS handshake completes and the peer
   certificate's SHA-256 is compared with the pinned value **before the request
   is written**. A mismatch closes the socket having sent nothing.
6. **Alias precondition.** The lookup must return exactly one alias, with
   exactly the expected name and type ``host`` and an integer ``id``;
   otherwise nothing is changed.
7. **Expiry re-checked** immediately before the change request.

Security considerations (AGENTS.md §3, §5):

* **Why ``CERT_NONE`` is not "no verification".** pfSense ships a self-signed
  web certificate, so chain validation has nothing to validate against. The
  owner chose pinning: the context accepts the handshake and this module then
  compares the exact certificate with :func:`hmac.compare_digest` and refuses
  on mismatch. That is a stronger statement than chain validation — it names
  one certificate, not any certificate a trusted CA would sign — and it fails
  closed when the firewall's certificate is regenerated.
* **No proxy.** ``http.client.HTTPSConnection`` connects directly to the
  declared IP literal; unlike ``urllib.request.urlopen`` it does not read
  ``https_proxy`` from the environment, so a configured proxy cannot sit in the
  middle (it would fail the pin in any case).
* **The key never leaves the request.** It is read from the environment at send
  time, validated as a bounded printable token, sent only in the
  ``X-API-Key`` header to the pinned peer, and never placed in an exception,
  an audit field or a return value.
* **The firewall's reply is untrusted input.** Bounded in size before parsing,
  parsed strictly (duplicate keys refused), and only named fields are read;
  any text from it that reaches the audit chain is truncated and
  delimiter-escaped.
* **An unknown outcome is reported as unknown.** If the change request was
  written but no valid answer came back, the action may or may not have taken
  effect; that is recorded as ``unknown`` and raised as
  :class:`OutcomeUnknownError` rather than guessed in either direction.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from agents.policies.approval import PolicyEngine
from agents.policies.audit import AuditLogger, escape_delimiter
from agents.policies.egress import (
    EgressAllowlist,
    EgressAllowlistError,
    EgressDenied,
    parse_address,
)
from agents.policies.execution_approval import VerifiedApproval
from agents.policies.principal import Principal
from agents.tools.guarded import ToolBlockedError, enforce
from agents.tools.pfsense import (
    PfSenseConfig,
    PfSenseDryRun,
    PfSenseError,
    PreparedChange,
    PreparedRequest,
    operation_for,
    parse_target,
)

#: Environment variable holding the pfREST API key, read only at send time.
PFSENSE_KEY_ENV = "IANUA_PFSENSE_API_KEY"
#: Policy labels. Each is a separate standing grant, so permitting the
#: read-only probe does not permit a change.
SEND_LABEL = "pfsense:send"
PROBE_LABEL = "pfsense:probe"

_REPO_ROOT = Path(__file__).resolve().parents[2]
#: Gitignored local declarations (owner decision: internal addresses stay out
#: of the public repository).
DEFAULT_LOCAL_CONFIG = _REPO_ROOT / "data" / "pfsense.local.json"
DEFAULT_LOCAL_EGRESS = _REPO_ROOT / "data" / "egress.local.json"

#: Per-read socket timeout, in seconds. A firewall that does not answer within
#: this is treated as not answering.
TIMEOUT_SECONDS = 10.0
#: Ceiling on any response body, checked before parsing.
MAX_RESPONSE_BYTES = 1 << 20
#: Ceiling on the local config file, checked before parsing.
_MAX_CONFIG_BYTES = 64 * 1024

_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
#: pfREST API keys are opaque printable tokens; bounded and whitespace-free so a
#: key can never inject a header.
_API_KEY = re.compile(r"^[!-~]{16,256}$")
_CONFIG_REQUIRED = frozenset({"version", "address", "port", "certificate_sha256", "protected"})
_CONFIG_OPTIONAL = frozenset({"block_alias", "isolate_alias"})


class LiveError(PfSenseError):
    """A live send or probe was refused before any change was made (fail closed)."""


class NotGrantedError(LiveError):
    """The policy bundle does not grant this label; nothing was attempted."""


class PinMismatchError(LiveError):
    """The peer's certificate is not the pinned one; nothing was sent."""


class OutcomeUnknownError(LiveError):
    """The change request was written but no valid answer arrived: verify on the firewall."""


@dataclass(frozen=True, slots=True)
class FirewallTarget:
    """Where the firewall is and which certificate it must present."""

    address: str
    port: int
    certificate_sha256: str

    def __post_init__(self) -> None:
        """Validate the address as a canonical IP literal, the port, and the pin.

        Uses the egress validator directly rather than the alias-target one:
        loopback cannot be an alias *target*, but as a firewall *address* it is
        how the test suite and a single-box lab reach a local stub, and the
        egress allow-list declares it on the same reasoning.
        """
        if type(self.address) is not str:
            raise LiveError("firewall address must be a string IP literal")
        try:
            parsed = parse_address(self.address)
        except EgressAllowlistError as exc:
            raise LiveError(f"firewall address: {exc}") from exc
        if str(parsed) != self.address:
            raise LiveError(f"firewall address must be written canonically as {str(parsed)!r}")
        if type(self.port) is not int or not 0 < self.port < 65536:
            raise LiveError("firewall port must be an integer in 1..65535")
        if type(self.certificate_sha256) is not str or not _FINGERPRINT.fullmatch(
            self.certificate_sha256
        ):
            raise LiveError("certificate_sha256 must be 64 lowercase hex characters")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise LiveError("JSON repeats a key")
    return dict(pairs)


def load_local_config(path: Path = DEFAULT_LOCAL_CONFIG) -> tuple[FirewallTarget, PfSenseConfig]:
    """Load ``data/pfsense.local.json``: the firewall target and the adapter config.

    Exact keys; a missing, oversized, malformed or unknown-keyed file raises.
    """
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LiveError(f"cannot read {path}: {exc.strerror}") from exc
    if len(raw) > _MAX_CONFIG_BYTES:
        raise LiveError(f"{path} is larger than {_MAX_CONFIG_BYTES} bytes")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except LiveError:
        raise
    except ValueError as exc:
        raise LiveError(f"{path} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise LiveError(f"{path} must hold a JSON object")
    keys = set(document)
    if not keys >= _CONFIG_REQUIRED or keys - _CONFIG_REQUIRED - _CONFIG_OPTIONAL:
        raise LiveError(
            f"{path} needs exactly {sorted(_CONFIG_REQUIRED)}, optionally {sorted(_CONFIG_OPTIONAL)}"
        )
    if document["version"] != 1 or type(document["version"]) is not int:
        raise LiveError(f"{path}: version must be 1")
    protected = document["protected"]
    if not isinstance(protected, list) or not all(type(p) is str for p in protected):
        raise LiveError(f"{path}: protected must be a list of IP literal strings")
    target = FirewallTarget(
        address=document["address"],
        port=document["port"],
        certificate_sha256=document["certificate_sha256"],
    )
    aliases = {k: document[k] for k in _CONFIG_OPTIONAL & keys}
    # The firewall's own management address is always protected, whether or not
    # the operator listed it: blocking it is how an operator loses the means to
    # undo the block.
    own = frozenset() if parse_address(target.address).is_loopback else frozenset({target.address})
    protected_set = frozenset(protected) | own
    return target, PfSenseConfig(protected=protected_set, **aliases)


def _api_key() -> str:
    value = os.environ.get(PFSENSE_KEY_ENV, "")
    if not _API_KEY.fullmatch(value):
        # Deliberately says nothing about the value: not its length, not a prefix.
        raise LiveError(f"{PFSENSE_KEY_ENV} is unset or not a plausible API key")
    return value


class PinnedConnection:
    """One HTTPS exchange with the pinned firewall. Never follows redirects."""

    def __init__(self, target: FirewallTarget, *, timeout: float = TIMEOUT_SECONDS) -> None:
        self.target = target
        self.timeout = timeout

    def _context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # Chain validation is replaced, not skipped: the exact certificate is
        # compared against the pin in exchange() before any request byte is sent.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def exchange(self, request: PreparedRequest, api_key: str) -> tuple[int, dict[str, Any]]:
        """Send ``request`` and return ``(status, parsed body)``.

        Raises :class:`PinMismatchError` before writing anything if the peer is
        not the pinned certificate, and :class:`LiveError` for a transport or
        parse failure.
        """
        connection = http.client.HTTPSConnection(
            self.target.address, self.target.port, timeout=self.timeout, context=self._context()
        )
        try:
            try:
                connection.connect()
            except (OSError, ssl.SSLError) as exc:
                raise LiveError(
                    f"could not establish TLS to the firewall: {type(exc).__name__}"
                ) from exc
            sock = connection.sock
            peer = sock.getpeercert(binary_form=True) if isinstance(sock, ssl.SSLSocket) else None
            # An absent certificate hashes to "", which can never equal a 64-hex pin.
            seen = hashlib.sha256(peer).hexdigest() if peer else ""
            if not hmac.compare_digest(seen, self.target.certificate_sha256):
                raise PinMismatchError(
                    "the firewall presented a certificate other than the pinned one; nothing was sent"
                )
            path = request.path + (f"?{urlencode(request.query)}" if request.query else "")
            body = None if request.body is None else json.dumps(request.body).encode("ascii")
            headers = {"X-API-Key": api_key, "Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            try:
                connection.request(request.method, path, body=body, headers=headers)
                response = connection.getresponse()
                payload = response.read(MAX_RESPONSE_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                raise LiveError(f"firewall exchange failed: {type(exc).__name__}") from exc
            if len(payload) > MAX_RESPONSE_BYTES:
                raise LiveError(f"firewall response exceeds {MAX_RESPONSE_BYTES} bytes")
            try:
                document = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicates)
            except LiveError:
                raise
            except ValueError as exc:
                raise LiveError("firewall response is not valid UTF-8 JSON") from exc
            if not isinstance(document, dict):
                raise LiveError("firewall response is not a JSON object")
            return response.status, document
        finally:
            connection.close()


class PfSenseLive:
    """Probe and change the declared lab firewall under every control in the module docstring."""

    def __init__(
        self,
        target: FirewallTarget,
        config: PfSenseConfig,
        *,
        engine: PolicyEngine,
        egress: EgressAllowlist,
        audit: AuditLogger,
        clock: Callable[[], float] = time.time,
        connection: PinnedConnection | None = None,
    ) -> None:
        if not isinstance(audit, AuditLogger):
            raise LiveError("a live firewall client requires an audit logger")
        self.target = target
        self.config = config
        self.engine = engine
        self.egress = egress
        self.audit = audit
        self._clock = clock
        self._adapter = PfSenseDryRun(config)
        self._connection = connection if connection is not None else PinnedConnection(target)
        self._used: set[str] = set()

    def _gate(self, label: str, actor: Principal) -> None:
        try:
            enforce(
                action_class="external_network",
                name=label,
                engine=self.engine,
                audit=self.audit,
                actor=actor,
            )
        except ToolBlockedError as exc:
            raise NotGrantedError(
                f"{label} is not granted: add {label!r} to the policy bundle's allow list "
                "(a reviewed edit) to permit it"
            ) from exc
        try:
            self.egress.require(self.target.address, self.target.port)
        except (EgressDenied, EgressAllowlistError) as exc:
            # The egress message names declared hosts; it is operator-facing and is
            # not forwarded into the audit reason.
            raise LiveError(
                "the firewall is not a declared lab host in the egress allow-list"
            ) from exc

    def _record(self, actor: str, action: str, decision: str, reason: str) -> None:
        self.audit.record(
            actor=actor,
            action=escape_delimiter(action[:256]),
            action_class="external_network",
            decision=decision,
            reason=escape_delimiter(reason[:512]),
        )

    def _resolve_alias(self, lookup: PreparedRequest, alias: str, api_key: str) -> int:
        return int(self._lookup_entry(lookup, alias, api_key)["id"])

    def _lookup_entry(self, lookup: PreparedRequest, alias: str, api_key: str) -> dict[str, Any]:
        """Run the alias lookup and return the one validated entry, or refuse."""
        status, document = self._connection.exchange(lookup, api_key)
        if status != 200 or document.get("code") != 200:
            raise LiveError(f"alias lookup for {alias} answered HTTP {status}")
        data = document.get("data")
        if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
            count = len(data) if isinstance(data, list) else "no list"
            raise LiveError(f"alias lookup for {alias} must return exactly one alias, got {count}")
        entry = data[0]
        if entry.get("name") != alias or entry.get("type") != "host":
            raise LiveError(f"alias lookup did not return a host alias named exactly {alias}")
        alias_id = entry.get("id")
        if type(alias_id) is not int or alias_id < 0:
            raise LiveError(f"alias {alias} has no usable integer id")
        return entry

    def verify(self, capability: str, target: str) -> dict[str, Any]:
        """Read-only: is ``target`` in the state ``capability`` would have left it?

        Settles an :class:`OutcomeUnknownError`: after an unknown ``block``, this
        answers whether the address is now in the block alias. Gated by the same
        read-only :data:`PROBE_LABEL` grant as :meth:`probe`, needs no approval
        because it changes nothing, and checks the same alias precondition as a
        send. The alias's ``address`` list must be a list of strings; anything
        else refuses rather than being read as "absent".
        """
        actor = Principal(component="pfsense")
        summary = f"verify {capability} {target}"
        try:
            role, operation = operation_for(capability)
            parse_target(target)
        except PfSenseError as exc:
            raise LiveError(str(exc)) from exc
        alias = self.config.alias_for(role)
        self._gate(PROBE_LABEL, actor)
        api_key = _api_key()
        lookup = PreparedRequest(
            method="GET", path="/api/v2/firewall/aliases", query=(("name", alias),)
        )
        try:
            entry = self._lookup_entry(lookup, alias, api_key)
            addresses = entry.get("address")
            if not isinstance(addresses, list) or not all(type(a) is str for a in addresses):
                raise LiveError(f"alias {alias} did not report an address list")
        except LiveError as exc:
            self._record("pfsense", summary, "deny", str(exc))
            raise
        present = target in addresses
        intended = operation == "append"
        settled = present is intended
        self._record(
            "pfsense",
            summary,
            "allow",
            f"alias {alias}: {target} {'present' if present else 'absent'}; "
            f"{'settled' if settled else 'NOT in the state ' + capability + ' intends'}",
        )
        return {
            "capability": capability,
            "target": target,
            "alias": alias,
            "present": present,
            "settled": settled,
        }

    def probe(self) -> dict[str, int]:
        """Read-only: confirm both aliases resolve, returning ``{alias: id}``.

        Gated by :data:`PROBE_LABEL`, a separate grant from sending. Changes
        nothing on the firewall. Use it before the first live send, to confirm
        the request shapes against the real device.
        """
        actor = Principal(component="pfsense")
        self._gate(PROBE_LABEL, actor)
        api_key = _api_key()
        found: dict[str, int] = {}
        try:
            for alias in (self.config.block_alias, self.config.isolate_alias):
                lookup = PreparedRequest(
                    method="GET", path="/api/v2/firewall/aliases", query=(("name", alias),)
                )
                found[alias] = self._resolve_alias(lookup, alias, api_key)
        except LiveError as exc:
            self._record("pfsense", "probe", "deny", str(exc))
            raise
        self._record("pfsense", "probe", "allow", f"aliases resolved: {sorted(found)}")
        return found

    def send(self, approval: VerifiedApproval) -> dict[str, Any]:
        """Apply the approved change to the firewall and return a summary.

        Raises :class:`LiveError` (nothing changed), :class:`PinMismatchError`
        (nothing sent) or :class:`OutcomeUnknownError` (the change request was
        written and its result could not be read — check the alias on the
        firewall before retrying).
        """
        if type(approval) is not VerifiedApproval:
            raise LiveError("a VerifiedApproval from execution_approval.authorize is required")
        actor = Principal(component="pfsense", caller=approval.approver)
        summary = f"{approval.capability} {approval.target}"
        try:
            self._gate(SEND_LABEL, actor)
            if approval.digest in self._used:
                raise LiveError("this approval has already been used to send")
            self._fresh(approval)
            change: PreparedChange = self._adapter.prepare(approval)
            api_key = _api_key()
            self._used.add(approval.digest)
            alias_id = self._resolve_alias(change.lookup, change.alias, api_key)
            self._fresh(approval)
        except LiveError as exc:
            self._record(actor.render(), summary, "deny", str(exc))
            raise
        except PfSenseError as exc:
            self._record(actor.render(), summary, "deny", str(exc))
            raise LiveError(str(exc)) from exc
        body = dict(change.change.body or {})
        body["id"] = alias_id
        request = PreparedRequest(method="PATCH", path=change.change.path, body=body)
        try:
            status, document = self._connection.exchange(request, api_key)
        except PinMismatchError as exc:
            self._record(actor.render(), summary, "deny", str(exc))
            raise
        except LiveError as exc:
            self._record(
                actor.render(),
                summary,
                "unknown",
                f"approval {approval.digest} change {change.digest}: {exc}; verify {change.alias}",
            )
            raise OutcomeUnknownError(
                f"the change was sent but its result is unknown ({exc}); "
                f"check alias {change.alias} on the firewall before retrying"
            ) from exc
        ok = status == 200 and document.get("code") == 200 and document.get("status") == "ok"
        response_id = str(document.get("response_id", ""))[:64]
        self._record(
            actor.render(),
            summary,
            "sent" if ok else "refused-by-firewall",
            f"approval {approval.digest} change {change.digest} alias {change.alias} "
            f"{change.operation} id {alias_id}: HTTP {status} {response_id}",
        )
        if not ok:
            raise LiveError(f"the firewall refused the change: HTTP {status} {response_id}")
        return {
            "capability": approval.capability,
            "target": approval.target,
            "alias": change.alias,
            "operation": change.operation,
            "approval_digest": approval.digest,
            "change_digest": change.digest,
            "status": status,
        }

    def _fresh(self, approval: VerifiedApproval) -> None:
        if self._clock() >= approval.expires_at:
            raise LiveError("approval expired before the change could be sent")
