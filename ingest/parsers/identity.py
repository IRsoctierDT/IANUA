"""Identity telemetry: Microsoft Entra ID sign-ins and Okta System Log.

Identity is where a modern intrusion usually becomes visible first — an
impossible-travel sign-in, an MFA fatigue burst, a session hijack. Both
sources report an outcome, and both are read the same careful way: the
provider's own result code is carried, and "no failure code" is recorded as
success only when the provider actually says so.

MFA state is extracted explicitly rather than being inferred from an absence,
because "MFA not satisfied" and "MFA field not present in this export" are
very different claims and only one of them is a finding.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ingest._coerce import dig, epoch, first, observables, strings, text
from ingest.parsers import Signature
from ingest.schema import Actor, Device, Endpoint, NormalizedEvent

# --------------------------------------------------------------------------
# Microsoft Entra ID (Azure AD) sign-in logs
# --------------------------------------------------------------------------


def _recognizes_entra(payload: Mapping[str, Any]) -> bool:
    if payload.get("userPrincipalName") is None:
        return False
    return any(
        key in payload
        for key in (
            "appDisplayName",
            "conditionalAccessStatus",
            "authenticationRequirement",
            "riskLevelDuringSignIn",
        )
    )


def _entra_mfa(payload: Mapping[str, Any]) -> str | None:
    """Whether MFA was satisfied, per the record's own fields — never inferred."""
    requirement = text(payload.get("authenticationRequirement"))
    if requirement is not None:
        return requirement
    details = payload.get("authenticationDetails")
    if isinstance(details, list) and details:
        methods = strings(
            [dig(item, "authenticationMethod") for item in details if isinstance(item, Mapping)],
            limit=8,
        )
        if methods:
            return ", ".join(methods)
    return None


def _parse_entra(payload: Mapping[str, Any]) -> NormalizedEvent:
    notes: list[str] = []
    timestamp = epoch(first(payload.get("createdDateTime"), payload.get("@timestamp")))
    if timestamp is None:
        notes.append("no usable timestamp on the record")

    upn = first(payload.get("userPrincipalName"))
    error_code = first(dig(payload, "status", "errorCode"))
    failure_reason = first(dig(payload, "status", "failureReason"))
    if error_code is None and failure_reason is None:
        notes.append("sign-in status absent; the outcome is unstated, not assumed successful")
        outcome = None
    else:
        outcome = "success" if error_code in ("0", None) else f"failure ({error_code})"

    ip = first(payload.get("ipAddress"))
    app = first(payload.get("appDisplayName"))
    mfa = _entra_mfa(payload)
    risk = first(payload.get("riskLevelDuringSignIn"), payload.get("riskState"))
    location = first(dig(payload, "location", "countryOrRegion"))

    message = " ".join(
        part
        for part in (
            "entra sign-in",
            f"upn={upn}" if upn else None,
            f"app={app}" if app else None,
            f"src={ip}" if ip else None,
            f"country={location}" if location else None,
            f"mfa={mfa}" if mfa else None,
            f"risk={risk}" if risk else None,
            f"outcome={outcome}" if outcome else None,
            f"reason={failure_reason}" if failure_reason else None,
        )
        if part
    )

    return NormalizedEvent(
        source_type="identity",
        vendor="entra-id",
        vendor_event_id=first(payload.get("id"), payload.get("correlationId")),
        timestamp=timestamp,
        message=message,
        activity="sign-in",
        parse_status="partial" if notes else "structured",
        actor=Actor(
            user_name=first(payload.get("userDisplayName")),
            user_principal=upn,
            user_uid=first(payload.get("userId")),
            identity=first(payload.get("appId")),
        ),
        device=Device(
            device_id=first(dig(payload, "deviceDetail", "deviceId")),
            hostname=first(dig(payload, "deviceDetail", "displayName")),
            os=first(dig(payload, "deviceDetail", "operatingSystem")),
        ),
        src_endpoint=Endpoint(ip=ip),
        observables=observables(ip, upn),
        notes=tuple(notes),
    )


# --------------------------------------------------------------------------
# Okta System Log
# --------------------------------------------------------------------------


def _recognizes_okta(payload: Mapping[str, Any]) -> bool:
    event_type = text(payload.get("eventType"))
    if event_type is None or "." not in event_type:
        return False
    # Okta's actor/outcome pair, both objects — distinctive enough that no
    # other supported source collides with it.
    return isinstance(payload.get("actor"), Mapping) and isinstance(payload.get("outcome"), Mapping)


def _parse_okta(payload: Mapping[str, Any]) -> NormalizedEvent:
    notes: list[str] = []
    timestamp = epoch(first(payload.get("published"), payload.get("@timestamp")))
    if timestamp is None:
        notes.append("no usable timestamp on the record")

    event_type = first(payload.get("eventType"))
    actor_login = first(dig(payload, "actor", "alternateId"), dig(payload, "actor", "displayName"))
    result = first(dig(payload, "outcome", "result"))
    reason = first(dig(payload, "outcome", "reason"))
    ip = first(dig(payload, "client", "ipAddress"))
    country = first(dig(payload, "client", "geographicalContext", "country"))
    behaviors = first(dig(payload, "debugContext", "debugData", "behaviors"))

    message = " ".join(
        part
        for part in (
            f"okta {event_type}",
            f"actor={actor_login}" if actor_login else None,
            f"src={ip}" if ip else None,
            f"country={country}" if country else None,
            f"outcome={result}" if result else None,
            f"reason={reason}" if reason else None,
            f"behaviors={behaviors}" if behaviors else None,
        )
        if part
    )

    return NormalizedEvent(
        source_type="identity",
        vendor="okta",
        vendor_event_id=first(payload.get("uuid")),
        timestamp=timestamp,
        message=message,
        activity=event_type,
        parse_status="partial" if notes else "structured",
        actor=Actor(
            user_name=first(dig(payload, "actor", "displayName")),
            user_principal=actor_login,
            user_uid=first(dig(payload, "actor", "id")),
        ),
        device=Device(
            hostname=first(dig(payload, "client", "device")),
            os=first(dig(payload, "client", "userAgent", "os")),
        ),
        src_endpoint=Endpoint(ip=ip),
        observables=observables(ip, actor_login),
        notes=tuple(notes),
    )


SIGNATURES: tuple[Signature, ...] = (
    Signature("entra-id", "identity", _recognizes_entra, _parse_entra),
    Signature("okta", "identity", _recognizes_okta, _parse_okta),
)
