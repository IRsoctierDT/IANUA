"""Cloud control-plane telemetry: AWS CloudTrail and Azure Activity Log.

Control-plane records are the domain the platform was most blind to: they
have no ``src_ip`` in the syslog sense, no flat message, and nothing a
keyword ladder can grip. They are also where the highest-consequence actions
live — a role assumed, a key created, a logging trail deleted.

Both parsers preserve the provider's own error/outcome field rather than
inferring success from an absence. A CloudTrail record with no ``errorCode``
means the call succeeded; a record whose ``errorCode`` we failed to read is a
different thing entirely, and the two are not collapsed.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ingest._coerce import dig, epoch, first, observables, text
from ingest.parsers import Signature
from ingest.schema import Actor, CloudContext, Device, Endpoint, NormalizedEvent

# --------------------------------------------------------------------------
# AWS CloudTrail
# --------------------------------------------------------------------------


def _recognizes_cloudtrail(payload: Mapping[str, Any]) -> bool:
    source = text(payload.get("eventSource"))
    if source is None or not source.endswith(".amazonaws.com"):
        return False
    return payload.get("eventName") is not None


def _cloudtrail_identity(payload: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """Return (principal label, ARN) from the several shapes ``userIdentity`` takes."""
    identity = payload.get("userIdentity")
    if not isinstance(identity, Mapping):
        return None, None
    arn = first(identity.get("arn"))
    label = first(
        identity.get("userName"),
        dig(identity, "sessionContext", "sessionIssuer", "userName"),
        identity.get("principalId"),
        identity.get("type"),
    )
    return label, arn


def _parse_cloudtrail(payload: Mapping[str, Any]) -> NormalizedEvent:
    notes: list[str] = []
    timestamp = epoch(payload.get("eventTime"))
    if timestamp is None:
        notes.append("no usable timestamp on the record")

    event_name = first(payload.get("eventName"))
    service = first(payload.get("eventSource"))
    principal, arn = _cloudtrail_identity(payload)
    if principal is None and arn is None:
        notes.append("userIdentity absent or unreadable; the actor is unattributed")

    error = first(payload.get("errorCode"))
    source_ip = first(payload.get("sourceIPAddress"))
    mfa = first(dig(payload, "userIdentity", "sessionContext", "attributes", "mfaAuthenticated"))

    message = " ".join(
        part
        for part in (
            f"cloudtrail {event_name}",
            f"service={service}" if service else None,
            f"principal={principal}" if principal else None,
            f"src={source_ip}" if source_ip else None,
            f"mfa={mfa}" if mfa else None,
            # Outcome is stated only when the provider stated it.
            f"error={error}" if error else "outcome=success",
        )
        if part
    )

    return NormalizedEvent(
        source_type="cloud",
        vendor="aws-cloudtrail",
        vendor_event_id=first(payload.get("eventID")),
        timestamp=timestamp,
        message=message,
        activity=event_name,
        parse_status="partial" if notes else "structured",
        actor=Actor(user_name=principal, identity=arn),
        device=Device(hostname=first(payload.get("userAgent"))),
        src_endpoint=Endpoint(ip=source_ip),
        cloud=CloudContext(
            provider="aws",
            account_uid=first(
                payload.get("recipientAccountId"), dig(payload, "userIdentity", "accountId")
            ),
            region=first(payload.get("awsRegion")),
            service=service,
        ),
        observables=observables(source_ip, arn),
        notes=tuple(notes),
    )


# --------------------------------------------------------------------------
# Azure Activity Log
# --------------------------------------------------------------------------


def _recognizes_azure(payload: Mapping[str, Any]) -> bool:
    operation = first(payload.get("operationName"), dig(payload, "operationName", "value"))
    if operation is None:
        return False
    return any(key in payload for key in ("resourceId", "resourceUri", "subscriptionId"))


def _azure_operation(payload: Mapping[str, Any]) -> str | None:
    """``operationName`` is a bare string in some exports, ``{value, localizedValue}`` in others."""
    raw = payload.get("operationName")
    if isinstance(raw, Mapping):
        return first(raw.get("value"), raw.get("localizedValue"))
    return text(raw)


def _parse_azure(payload: Mapping[str, Any]) -> NormalizedEvent:
    notes: list[str] = []
    timestamp = epoch(
        first(payload.get("eventTimestamp"), payload.get("time"), payload.get("@timestamp"))
    )
    if timestamp is None:
        notes.append("no usable timestamp on the record")

    operation = _azure_operation(payload)
    caller = first(payload.get("caller"), dig(payload, "claims", "name"))
    status = first(
        dig(payload, "status", "value"), payload.get("status"), dig(payload, "resultType")
    )
    resource = first(payload.get("resourceId"), payload.get("resourceUri"))
    caller_ip = first(payload.get("callerIpAddress"))

    message = " ".join(
        part
        for part in (
            f"azure-activity {operation}",
            f"caller={caller}" if caller else None,
            f"src={caller_ip}" if caller_ip else None,
            f"status={status}" if status else None,
            f"resource={resource}" if resource else None,
        )
        if part
    )

    return NormalizedEvent(
        source_type="cloud",
        vendor="azure-activity",
        vendor_event_id=first(payload.get("correlationId"), payload.get("eventDataId")),
        timestamp=timestamp,
        message=message,
        activity=operation,
        parse_status="partial" if notes else "structured",
        actor=Actor(user_principal=caller, identity=first(dig(payload, "claims", "appid"))),
        src_endpoint=Endpoint(ip=caller_ip),
        cloud=CloudContext(
            provider="azure",
            account_uid=first(payload.get("subscriptionId"), payload.get("tenantId")),
            region=first(payload.get("location")),
            service=first(payload.get("resourceProvider"), payload.get("category")),
        ),
        observables=observables(caller_ip, resource),
        notes=tuple(notes),
    )


SIGNATURES: tuple[Signature, ...] = (
    Signature("aws-cloudtrail", "cloud", _recognizes_cloudtrail, _parse_cloudtrail),
    Signature("azure-activity", "cloud", _recognizes_azure, _parse_azure),
)
