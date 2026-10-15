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

Anything unrecognized normalizes to `source_type="unknown"` with a note explaining why.
That is a real outcome, not a failure to try. What it carries depends on whether there was
a record to carry: a *decoded* record keeps the paths some parser models and nothing else,
with a note naming the keys it withheld; free-form text keeps its text, because there is no
structure there to project.

## Architecture

```
raw record ──> size / depth bounds ──> detect_source() ──> parser ──> NormalizedEvent
                     │                       │                            ▲
                     │                       │                            │
                     │                       │        raw_excerpt = project(record,
                     │                       │                 signature.fields)
                     │                       └── ambiguous or unclaimed ──> unknown + note,
                     │                              projected through MODELLED_FIELDS
                     └── over budget ──> excerpt + note (never dropped)
```

Each parser module exports a `SIGNATURES` tuple pairing a *recognizer* (is this record
mine?), a *parser* (read it), and the *payload paths* the two of them read.
`ingest/normalize.py` is the only place that knows the full set — and the only place that
builds an excerpt, so no parser can forget one and none can widen one.

## The four rules

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
4. **Retain only what a parser modelled.** `raw_excerpt` is rebuilt from the paths a
   signature declared, never copied from the record. `store/` refuses `UPDATE` and keys
   rows by a digest of the projection, so there is no later redaction pass — what this
   package writes is what is kept, which makes the question "what does an excerpt
   contain?" the whole of the platform's retention posture (AGENTS.md §5, stage 6
   amendment).

## Notable deliberate choices

- **`timestamp` is never back-filled.** A source with no usable timestamp yields `None`
  and a note. Substituting "now" would fabricate ordering that correlation later depends
  on.
- **There is no field for an email body, and no excerpt to smuggle one in.**
  `EmailContext` carries `subject`, `sender`, `recipients`, `message_id`,
  `delivery_action`, and `urls` — the metadata where the detection value lives. A security
  test walks every parser's AST and fails the build if any of them reads a body-shaped
  field, in any domain. Both of those were true while a `Body` still reached
  `raw_excerpt`, because the excerpt was a copy of the decoded record: the two controls
  covered what a parser *reads* and what the schema *declares*, and neither covered what
  the excerpt *copied*. It is now rebuilt from declared paths, so the rule holds where it
  is actually tested — in a stored row.
- **The allow-list is declared beside the parser that justifies it.** Each `Signature`
  names the payload paths it reads, as tuples of keys so that Zeek's literally-dotted
  `id.orig_h` is a one-component path rather than an ambiguity. Over-declaring is made
  safe rather than merely discouraged: a declared path landing on an object contributes
  its key *names* and never its values, so a container declared by mistake degrades to
  shape instead of leaking content.
- **Absent is not empty.** `to_match_view()` omits fields the source did not carry rather
  than rendering them as `""`, because an empty string reads downstream as "the source
  said this is blank" — a different and false claim.
- **A vendor's verdict is carried, never restated.** A Suricata signature name, a
  Defender `DeliveryAction`, an Entra error code: these are evidence, recorded verbatim.
  The platform does not re-derive them and does not present them as its own conclusion.
- **Every bound is applied where it is asserted.** `NormalizedEvent.bounded()` sits beside
  `from_dict`, which validates the same bounds on read, and `normalize()` applies it to
  every parsed event. `message` is the field that needed it: it is assembled from several
  separately bounded values and nothing re-bounded the result, so an ordinary
  encoded-PowerShell `CommandLine` produced an event `append` accepted and `query` could
  never read back. Truncation demotes `parse_status` and adds a note rather than happening
  silently.
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
exhaustion from hostile records, and message bodies entering the corpus. The residual on
the third is named rather than waved at: free-form text that never decoded into a record
is still carried verbatim, so a body pasted into a syslog line reaches an excerpt. There
is no structure there to project, and dropping the text would manufacture the blind spot
rule 2 exists to close.

## Future Enhancements

`correlation/` — entity resolution across domains and incident assembly — is the
remaining half of the XDR path, tracked as XDR-2 in
`docs/DETECTION_INTELLIGENCE_PLAN.md`. It is deliberately a separate package so this
parsing surface can be reasoned about, and statically analyzed, without the stateful
half.
