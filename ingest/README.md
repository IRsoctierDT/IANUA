# `ingest/` — multi-source telemetry normalization

**Purpose** · Translate endpoint, network, cloud, identity, and email telemetry into one
canonical event, so every layer above it stops caring which product emitted a record.
**Risk level** · Moderate — this is the platform's largest untrusted-input surface.
**Skill level required** · Detection engineer familiar with the source formats.
**Deployment complexity** · None. Pure stdlib; no service, no state, no configuration.

---

## Executive Summary

Before this package, the platform reasoned over syslog-shaped text through a keyword
classifier. That works for one domain and fails for the rest: an AWS CloudTrail
`AssumeRole` record or a Microsoft Entra sign-in has no `src_ip`, no flat message, and
nothing a keyword ladder can grip.

`ingest/` normalizes ten formats across five domains into a single
[`NormalizedEvent`](./schema.py). Downstream — the SOC classifier, the ATT&CK mapping
engine, the behavioral matcher, the response planner — reads that one shape. Only this
package knows that CloudTrail spells it `sourceIPAddress` and Suricata spells it
`src_ip`.

## Supported sources

| Domain | Vendor | Recognized by |
|---|---|---|
| endpoint | Sysmon | provider/channel naming Sysmon, plus an event ID |
| endpoint | auditd | a known auditd record `type` plus a corroborating auditd field |
| network | Zeek | the dotted connection tuple (`id.orig_h` / `id.resp_h`) |
| network | Suricata EVE | a known `event_type` plus `src_ip` **and** `dest_ip` |
| cloud | AWS CloudTrail | `eventSource` ending `.amazonaws.com`, plus `eventName` |
| cloud | Azure Activity | `operationName` plus a resource/subscription identifier |
| identity | Microsoft Entra ID | `userPrincipalName` plus a sign-in-specific field |
| identity | Okta System Log | dotted `eventType` plus `actor` **and** `outcome` objects |
| email | Defender for Office 365 | `NetworkMessageId` plus an email field |
| email | Google Workspace | a message id plus a sender/recipient field |

Anything unrecognized normalizes to `source_type="unknown"` with the text carried and a
note explaining why. That is a real outcome, not a failure to try.

## Architecture

```
raw record ──> size / depth bounds ──> detect_source() ──> parser ──> NormalizedEvent
                     │                       │
                     │                       └── ambiguous or unclaimed ──> unknown + note
                     └── over budget ──> excerpt + note (never dropped)
```

Each parser module exports a `SIGNATURES` tuple pairing a *recognizer* (is this record
mine?) with a *parser* (read it). `ingest/normalize.py` is the only place that knows the
full set.

## The three rules

1. **Recognize, never guess.** A record is parsed only when exactly one signature claims
   it on distinctive keys. Two signatures claiming the same record means it is attributed
   to *neither* — overlapping formats are a bug to fix at the signature, not to paper over
   by taking whichever registered first. Mis-attributing a record produces a confident,
   wrong analysis, which is worse than an explicit "not recognized".
2. **Degrade visibly, don't drop.** Oversized, over-nested, undecodable, and
   type-confused records still yield an event, with `parse_status` demoted to `partial`
   and a note saying what happened. Silently discarding telemetry manufactures the blind
   spot this layer exists to close.
3. **No ambient authority.** No clock, filesystem, network, subprocess, or dynamic exec —
   asserted over the package's AST in `tests/security/test_ingest_hardening.py`. Given
   the same bytes, this package returns the same event.

## Notable deliberate choices

- **`timestamp` is never back-filled.** A source with no usable timestamp yields `None`
  and a note. Substituting "now" would fabricate ordering that correlation later depends
  on.
- **There is no field for an email body.** `EmailContext` carries `subject`, `sender`,
  `recipients`, `message_id`, `delivery_action`, and `urls` — the metadata where the
  detection value lives. A security test walks every parser's AST and fails the build if
  any of them reads a body-shaped field, in any domain.
- **Absent is not empty.** `to_match_view()` omits fields the source did not carry rather
  than rendering them as `""`, because an empty string reads downstream as "the source
  said this is blank" — a different and false claim.
- **A vendor's verdict is carried, never restated.** A Suricata signature name, a
  Defender `DeliveryAction`, an Entra error code: these are evidence, recorded verbatim.
  The platform does not re-derive them and does not present them as its own conclusion.
- **`activity` stays an enumerable vocabulary.** A Suricata alert's free-text signature
  lives in `message`, not in `activity` — otherwise the OCSF classification table keyed
  on it would be meaningless.

## Usage

```python
from ingest import normalize, normalize_many

event = normalize(cloudtrail_record)      # mapping, JSON string, or bytes
event.source_type                          # "cloud"
event.to_dict()                            # allow-list projection, JSON-ready
event.to_match_view()                      # flat dict for sigma_eval / mapping engine

events = normalize_many(lines)             # order preserved; one bad record is isolated
```

`normalize()` raises only `UnsupportedInputError`, and only for a Python type that cannot
be telemetry at all. Malformed *content* degrades instead.

## Risks

Enumerated with mitigations in `DESIGN.md` §8; the trust argument is boundary 9 in §5.
The three that shaped the design: mis-attribution to the wrong parser, resource
exhaustion from hostile records, and message bodies entering the corpus.

## Future Enhancements

`correlation/` — entity resolution across domains and incident assembly — is the
remaining half of the XDR path, tracked as XDR-2 in
`docs/DETECTION_INTELLIGENCE_PLAN.md`. It is deliberately a separate package so this
parsing surface can be reasoned about, and statically analyzed, without the stateful
half.
