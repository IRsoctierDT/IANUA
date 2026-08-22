"""Network telemetry: Zeek (conn/dns/http) and Suricata EVE.

Zeek describes what happened on the wire; Suricata says what a signature
thought of it. Both are carried, and the difference is preserved: a Suricata
alert arrives with its own vendor verdict, which is recorded as the event's
activity rather than being re-derived. A verdict a tool already reached is
evidence, not a starting point for guessing.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ingest._coerce import dig, epoch, first, observables, text
from ingest.parsers import Signature
from ingest.schema import Actor, Device, Endpoint, NormalizedEvent

# --------------------------------------------------------------------------
# Zeek
# --------------------------------------------------------------------------

#: Zeek log streams this parser reads. Others still normalize (as the stream
#: name), which keeps a new Zeek log visible instead of dropping it.
_ZEEK_STREAMS = frozenset({"conn", "dns", "http", "ssl", "files", "notice", "weird"})


def _zeek_stream(payload: Mapping[str, Any]) -> str | None:
    return first(payload.get("_path"), payload.get("_write_ts_path"))


def _recognizes_zeek(payload: Mapping[str, Any]) -> bool:
    # Zeek's connection 4-tuple keys are literally dotted; nothing else uses
    # this exact spelling, which makes it a reliable discriminator.
    tuple_keys = {"id.orig_h", "id.resp_h"} <= set(payload)
    return tuple_keys or (_zeek_stream(payload) in _ZEEK_STREAMS and "uid" in payload)


def _parse_zeek(payload: Mapping[str, Any]) -> NormalizedEvent:
    notes: list[str] = []
    stream = _zeek_stream(payload) or "conn"
    if stream not in _ZEEK_STREAMS:
        notes.append(f"unrecognized Zeek stream {stream!r}; fields read generically")

    timestamp = epoch(first(payload.get("ts"), payload.get("@timestamp")))
    if timestamp is None:
        notes.append("no usable timestamp on the record")

    src_ip = first(payload.get("id.orig_h"), dig(payload, "id", "orig_h"))
    dst_ip = first(payload.get("id.resp_h"), dig(payload, "id", "resp_h"))
    src_port = first(payload.get("id.orig_p"), dig(payload, "id", "orig_p"))
    dst_port = first(payload.get("id.resp_p"), dig(payload, "id", "resp_p"))
    query = first(payload.get("query"), payload.get("server_name"), payload.get("host"))
    proto = first(payload.get("proto"), payload.get("service"))

    message = " ".join(
        part
        for part in (
            f"zeek {stream}",
            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}" if src_ip and dst_ip else None,
            f"proto={proto}" if proto else None,
            f"query={query}" if query else None,
            f"uri={text(payload.get('uri'))}" if payload.get("uri") else None,
        )
        if part
    )

    return NormalizedEvent(
        source_type="network",
        vendor="zeek",
        vendor_event_id=first(payload.get("uid")),
        timestamp=timestamp,
        message=message,
        activity=stream,
        parse_status="partial" if notes else "structured",
        device=Device(hostname=first(payload.get("_node"))),
        src_endpoint=Endpoint(ip=src_ip, port=src_port),
        dst_endpoint=Endpoint(ip=dst_ip, port=dst_port, domain=query),
        observables=observables(src_ip, dst_ip, query, payload.get("uri")),
        notes=tuple(notes),
    )


# --------------------------------------------------------------------------
# Suricata EVE
# --------------------------------------------------------------------------

_SURICATA_EVENT_TYPES = frozenset(
    {"alert", "dns", "http", "tls", "flow", "fileinfo", "anomaly", "ssh", "smb"}
)


def _recognizes_suricata(payload: Mapping[str, Any]) -> bool:
    event_type = text(payload.get("event_type"))
    if event_type is None or event_type.lower() not in _SURICATA_EVENT_TYPES:
        return False
    # EVE always carries the flow endpoints as src_ip/dest_ip — note the
    # "dest", not "dst", spelling, which is Suricata's own.
    return "src_ip" in payload and "dest_ip" in payload


def _parse_suricata(payload: Mapping[str, Any]) -> NormalizedEvent:
    notes: list[str] = []
    event_type = (text(payload.get("event_type")) or "").lower()
    timestamp = epoch(first(payload.get("timestamp"), payload.get("@timestamp")))
    if timestamp is None:
        notes.append("no usable timestamp on the record")

    src_ip = first(payload.get("src_ip"))
    dst_ip = first(payload.get("dest_ip"))
    signature = first(dig(payload, "alert", "signature"))
    severity = first(dig(payload, "alert", "severity"))
    query = first(dig(payload, "dns", "rrname"), dig(payload, "http", "hostname"))

    message = " ".join(
        part
        for part in (
            f"suricata {event_type}",
            f"{src_ip}:{first(payload.get('src_port'))} -> "
            f"{dst_ip}:{first(payload.get('dest_port'))}"
            if src_ip and dst_ip
            else None,
            f"signature={signature}" if signature else None,
            f"severity={severity}" if severity else None,
            f"query={query}" if query else None,
        )
        if part
    )

    return NormalizedEvent(
        source_type="network",
        vendor="suricata",
        vendor_event_id=first(dig(payload, "alert", "signature_id"), payload.get("flow_id")),
        timestamp=timestamp,
        message=message,
        # ``activity`` stays a stable vocabulary term (Suricata's own
        # ``event_type``) so downstream tables can key on it. The sensor's
        # signature verdict is carried verbatim in ``message`` instead of
        # being promoted into a field whose values must stay enumerable.
        activity=event_type,
        parse_status="partial" if notes else "structured",
        actor=Actor(user_name=first(dig(payload, "ssh", "client", "software_version"))),
        device=Device(hostname=first(payload.get("host"))),
        src_endpoint=Endpoint(ip=src_ip, port=first(payload.get("src_port"))),
        dst_endpoint=Endpoint(ip=dst_ip, port=first(payload.get("dest_port")), domain=query),
        observables=observables(src_ip, dst_ip, query, dig(payload, "http", "url")),
        notes=tuple(notes),
    )


SIGNATURES: tuple[Signature, ...] = (
    Signature("zeek", "network", _recognizes_zeek, _parse_zeek),
    Signature("suricata", "network", _recognizes_suricata, _parse_suricata),
)
