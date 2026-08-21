"""Email telemetry: Microsoft Defender for Office 365 and Google Workspace.

Email is the most sensitive corpus the platform touches, so this module is
written to a stricter rule than the others: **it never reads a message body.**
There is no field for one in ``EmailContext``, and there is no read of one
here — not ``Body``, not ``snippet``, not ``payload.parts``. The detection
value in mail telemetry lives in the metadata (who sent it, to whom, what the
platform already did with it, which URLs it carried), and the body adds
liability without adding signal (AGENTS.md §5 — sensitive by default).

The delivery verdict a mail platform already reached is carried verbatim.
``Blocked`` from Defender means Defender blocked it; the platform does not
restate that as its own finding.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ingest._coerce import epoch, first, observables, strings
from ingest.parsers import Signature
from ingest.schema import (
    MAX_OBSERVABLES,
    Actor,
    EmailContext,
    Endpoint,
    NormalizedEvent,
)

#: A single message can carry a large recipient list; bound it the same way
#: every other untrusted sequence is bounded.
_MAX_RECIPIENTS = 32

# --------------------------------------------------------------------------
# Microsoft Defender for Office 365 — EmailEvents / EmailUrlInfo
# --------------------------------------------------------------------------


def _recognizes_defender(payload: Mapping[str, Any]) -> bool:
    if payload.get("NetworkMessageId") is None:
        return False
    return any(
        key in payload
        for key in ("SenderFromAddress", "RecipientEmailAddress", "DeliveryAction", "ThreatTypes")
    )


def _parse_defender(payload: Mapping[str, Any]) -> NormalizedEvent:
    notes: list[str] = []
    timestamp = epoch(first(payload.get("Timestamp"), payload.get("@timestamp")))
    if timestamp is None:
        notes.append("no usable timestamp on the record")

    sender = first(payload.get("SenderFromAddress"), payload.get("SenderMailFromAddress"))
    recipients = strings(payload.get("RecipientEmailAddress"), limit=_MAX_RECIPIENTS)
    subject = first(payload.get("Subject"))
    delivery = first(payload.get("DeliveryAction"))
    threat = first(payload.get("ThreatTypes"))
    sender_ip = first(payload.get("SenderIPv4"), payload.get("SenderIPv6"))
    urls = strings(payload.get("UrlList"), limit=MAX_OBSERVABLES)
    auth = first(payload.get("AuthenticationDetails"))
    # Defender writes the literal string "None" when it took no action, so it
    # is carried as evidence in the message rather than promoted into
    # ``activity``, whose values have to stay an enumerable vocabulary.
    email_action = first(payload.get("EmailAction"))

    if delivery is None:
        notes.append("no DeliveryAction on the record; the mail platform's verdict is unknown")

    message = " ".join(
        part
        for part in (
            "defender-o365 email",
            f"sender={sender}" if sender else None,
            f"recipients={len(recipients)}" if recipients else None,
            f"subject={subject}" if subject else None,
            f"delivery={delivery}" if delivery else None,
            f"threat={threat}" if threat else None,
            f"auth={auth}" if auth else None,
            f"action={email_action}" if email_action else None,
        )
        if part
    )

    return NormalizedEvent(
        source_type="email",
        vendor="defender-o365",
        vendor_event_id=first(payload.get("NetworkMessageId")),
        timestamp=timestamp,
        message=message,
        activity="email delivery",
        parse_status="partial" if notes else "structured",
        actor=Actor(user_principal=sender),
        src_endpoint=Endpoint(ip=sender_ip, domain=first(payload.get("SenderFromDomain"))),
        email=EmailContext(
            sender=sender,
            recipients=recipients,
            subject=subject,
            message_id=first(payload.get("InternetMessageId"), payload.get("NetworkMessageId")),
            delivery_action=delivery,
            urls=urls,
        ),
        observables=observables(sender_ip, sender, *urls),
        notes=tuple(notes),
    )


# --------------------------------------------------------------------------
# Google Workspace — Email Log Search / Gmail log export
# --------------------------------------------------------------------------


def _recognizes_workspace(payload: Mapping[str, Any]) -> bool:
    if payload.get("message_id") is None and payload.get("rfc2822_message_id") is None:
        return False
    return any(
        key in payload
        for key in ("sender_address", "recipient_address", "recipient_addresses", "event_info")
    )


def _parse_workspace(payload: Mapping[str, Any]) -> NormalizedEvent:
    notes: list[str] = []
    timestamp = epoch(first(payload.get("event_timestamp"), payload.get("@timestamp")))
    if timestamp is None:
        notes.append("no usable timestamp on the record")

    sender = first(payload.get("sender_address"), payload.get("from_address"))
    recipients = strings(
        payload.get("recipient_addresses") or payload.get("recipient_address"),
        limit=_MAX_RECIPIENTS,
    )
    subject = first(payload.get("subject"))
    delivery = first(payload.get("status"), payload.get("delivery_status"), payload.get("action"))
    spam = first(payload.get("spam_classification"), payload.get("is_spam"))
    sender_ip = first(payload.get("sender_ip"), payload.get("source_ip"))
    urls = strings(payload.get("urls"), limit=MAX_OBSERVABLES)
    event_info = first(payload.get("event_info"))

    if delivery is None:
        notes.append("no delivery status on the record; the mail platform's verdict is unknown")

    message = " ".join(
        part
        for part in (
            "workspace email",
            f"sender={sender}" if sender else None,
            f"recipients={len(recipients)}" if recipients else None,
            f"subject={subject}" if subject else None,
            f"status={delivery}" if delivery else None,
            f"spam={spam}" if spam else None,
            f"info={event_info}" if event_info else None,
        )
        if part
    )

    return NormalizedEvent(
        source_type="email",
        vendor="google-workspace",
        vendor_event_id=first(payload.get("message_id"), payload.get("rfc2822_message_id")),
        timestamp=timestamp,
        message=message,
        activity="email delivery",
        parse_status="partial" if notes else "structured",
        actor=Actor(user_principal=sender),
        src_endpoint=Endpoint(ip=sender_ip),
        email=EmailContext(
            sender=sender,
            recipients=recipients,
            subject=subject,
            message_id=first(payload.get("rfc2822_message_id"), payload.get("message_id")),
            delivery_action=delivery,
            urls=urls,
        ),
        observables=observables(sender_ip, sender, *urls),
        notes=tuple(notes),
    )


#: Field names that would carry message content. Nothing in this module reads
#: them; the tuple exists so ``tests/security/test_ingest_hardening.py`` can
#: assert their absence from the module source, making the rule enforceable
#: rather than merely documented.
FORBIDDEN_CONTENT_FIELDS: tuple[str, ...] = (
    "Body",
    "BodyText",
    "snippet",
    "message_body",
    "raw_message",
    "textContent",
)


SIGNATURES: tuple[Signature, ...] = (
    Signature("defender-o365", "email", _recognizes_defender, _parse_defender),
    Signature("google-workspace", "email", _recognizes_workspace, _parse_workspace),
)
