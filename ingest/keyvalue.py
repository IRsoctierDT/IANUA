# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Decode ``key=value`` log text into a mapping the existing signatures claim.

Until now ``normalize`` parsed only text beginning with ``{`` or ``[``:
everything else was carried as an excerpt with ``parse_status="text"`` and no
structured fields. That is honest — it degrades visibly rather than guessing —
but it meant the two most valuable sources on a Linux node were collectable and
not correlatable. Measured, before this module existed:

===================================  ==========================
line shape                           result
===================================  ==========================
Suricata EVE / Zeek / CloudTrail     parsed, correlated
auditd ``type=SYSCALL … comm=bash``  ``unknown`` / ``text``
``/var/log/auth.log`` freeform       ``unknown`` / ``text``
===================================  ==========================

This closes the first of those two. It adds **no signature and no parser**: the
auditd recognizer in ``ingest/parsers/endpoint.py`` already claims
``{type, node, auid, comm}`` and already reads auditd's own clock out of
``msg=audit(<epoch>.<ms>:<serial>)``. It was written expecting exactly this
mapping; nothing was producing one. So this is a decoder, not a parser, and it
lives beside ``normalize`` rather than in ``parsers/`` — that directory is one
module per *domain*, and a text encoding is not a domain.

Freeform syslog (``Failed password for svc-deploy from 198.51.100.7``) is
deliberately still out of scope. Extracting it means regex patterns against
unversioned vendor message strings, which is the most defect-prone code in any
log pipeline, and it belongs in its own reviewed change rather than riding
along with a decoder.

Security considerations (AGENTS.md §3, §5):

* **Claims a line only when it is predominantly structured.** A prose line
  with one incidental ``=`` must not become a two-field "event" — that would
  manufacture telemetry, which is worse than carrying the line as text. The
  thresholds below are the whole control, and
  ``tests/security/test_keyvalue_hardening.py`` is where they are held.
* **Bounded before it is useful.** A pathological line cannot create an
  unbounded mapping, an unbounded key, or an unbounded value; every limit is a
  named constant, asserted against fixed literals rather than against itself.
  Be precise about what the bounds do and do not give you: the excess is
  **dropped silently** — this function returns a mapping and has nowhere to
  put a note, so a record whose value was cut at ``MAX_VALUE_LEN`` or whose
  pairs stopped at ``MAX_PAIRS`` is stored looking complete. An earlier draft
  of this list claimed the record was "marked degraded by ``ingest/``'s
  existing machinery"; nothing does that, and the claim is corrected here
  rather than left to be discovered. Surfacing it means giving the decoder a
  way to report, which is a signature change and its own reviewed commit.
* **Pure.** No clock, no filesystem, no network, no subprocess, no ``eval``.
  The package's AST invariants already assert this and now cover this module.
* **Nothing is executed or resolved.** A value is text. ``comm=/bin/sh`` is a
  string that happens to look like a path, and this module does not care.
"""

from __future__ import annotations

import re

#: How many nested payloads one line may be re-scanned for pairs. Only the
#: single-quoted value of a *repeated* ``msg`` is one (see
#: :func:`_merge_nested`); auditd writes exactly one, and the bound is here so
#: a crafted line cannot turn one decode into many.
MAX_NESTED_PAYLOADS = 4

#: Smallest number of pairs that makes a line "structured" rather than prose
#: that happens to contain an equals sign.
#:
#: Two, not one. One pair matches far too much ordinary log text (``error:
#: retries=3 giving up``) and claiming it would hand ``ingest/`` a mapping of
#: one field — enough to look like data and never enough to be data. Two
#: adjacent pairs is the point where a line is describing fields rather than
#: mentioning one.
MIN_PAIRS = 2

#: Fraction of the line's non-space characters that must be inside recognized
#: pairs. auditd and logfmt lines run ~100%; a prose line with two incidental
#: pairs runs far lower, which is exactly the case :data:`MIN_PAIRS` alone
#: cannot separate.
MIN_COVERAGE = 0.6

#: Ceilings. A single malformed line cannot exhaust memory or smuggle a huge
#: field past the schema's own bounds.
MAX_PAIRS = 256
MAX_KEY_LEN = 64
MAX_VALUE_LEN = 4096

#: One ``key=value`` token. The key is identifier-shaped, deliberately
#: narrower than "anything before an equals sign", so ``a=1 b=2`` in the middle
#: of a sentence does not drag the preceding words in as a key. The value is
#: either double-quoted (auditd quotes values containing spaces), single-quoted,
#: or an unquoted run of non-space characters — which is what keeps auditd's
#: ``msg=audit(1760000000.1:1)`` in one piece, parentheses, dots, colons and all.
_PAIR = re.compile(
    rf"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{{0,{MAX_KEY_LEN - 1}}})="
    r'(?:"(?P<dq>[^"]*)"|\'(?P<sq>[^\']*)\'|(?P<bare>[^\s]*))'
)


def decode(line: str) -> dict[str, str] | None:
    """Return the line's ``key=value`` pairs, or ``None`` if it is not that shape.

    ``None`` means "this is not structured text" and the caller should carry the
    line as an excerpt — the behaviour every non-JSON line had before this
    module. It is not an error: most log lines in the world are prose.

    **The first occurrence of a key wins**, which is deliberately *not* the
    last-wins convention logfmt readers use. Two reasons, and the first was
    found by review: a real auditd ``USER_AUTH``/``CRED_ACQ``/``USER_CMD``
    record carries ``msg=audit(<epoch>.<ms>:<serial>)`` *and* a second
    ``msg='op=… acct=… res=…'``, so last-wins clobbered the clock form and
    every authentication and sudo record landed undated — the records an
    analyst most wants placed in time. The second reason is defensive: a later
    pair cannot overwrite an earlier one, so a line whose tail an attacker
    influences cannot restate the ``user`` or ``host`` its head already
    declared.

    auditd's ``a0``/``a1`` argv keys are distinct names, so the EXECVE
    reassembly in ``parsers/endpoint.py`` is unaffected either way.

    **Quoting follows auditd, which has no escapes, and that is a residual.**
    A quoted value ends at the next matching quote whatever precedes it, so a
    logfmt writer that escapes correctly (``\\"``) still lets the string it
    escaped break out to top level; single quotes behave the same.
    Measured: ``type=USER_LOGIN user="a\\" comm=sshd timestamp=1.0 x=\\""``
    decodes ``comm`` and ``timestamp`` as top-level keys and is claimed as
    auditd, ``structured``, dated ``1.0``. First-wins does not help — the keys
    are new. Honoring ``\\"`` changes how every auditd value ending in a
    backslash is read, and what auditd writes there was not measured, so which
    convention wins is the owner's decision; a value the application did not
    quote or escape at all is the same case and no decoder of this shape can
    close it.

    Args:
        line: One decoded log line, newline already stripped.

    Returns:
        A mapping of at least :data:`MIN_PAIRS` pairs covering at least
        :data:`MIN_COVERAGE` of the line's non-space characters, or ``None``.
    """
    pairs: dict[str, str] = {}
    payloads: list[str] = []
    covered = 0
    for match in _PAIR.finditer(line):
        # Coverage is counted for every pair found, including those past the
        # cap. Stopping the scan instead would make a *denser* line look
        # sparser: a 1000-pair record would score coverage over only its first
        # MAX_PAIRS and be rejected as prose, which is the opposite of the
        # intent. The cap bounds what is *kept*, not what is *measured*.
        covered += len(match.group(0).replace(" ", ""))
        key = match.group("key")
        quoted = match.group("dq")
        if quoted is None:
            quoted = match.group("sq")
        # Only auditd's own nesting is re-scanned: a single-quoted ``msg`` that
        # *repeats* an earlier one — precisely the pair first-occurrence-wins
        # drops just below. Any other quoted value is an application's field
        # (``user="…"``, ``detail="…"``), and mining it let a username holding
        # ``msg=audit(1.0:1)`` or ``comm=sshd timestamp=1.0`` claim and date
        # the line as auditd. See :func:`_merge_nested`.
        nested = match.group("sq")
        if (
            key == "msg"
            and key in pairs
            and nested is not None
            and "=" in nested
            and len(payloads) < MAX_NESTED_PAYLOADS
        ):
            payloads.append(nested)
        if len(pairs) >= MAX_PAIRS:
            continue
        if key in pairs:
            continue  # first occurrence wins — see the docstring
        value = quoted if quoted is not None else (match.group("bare") or "")
        pairs[key] = value[:MAX_VALUE_LEN]

    if len(pairs) < MIN_PAIRS:
        return None
    dense = len(line.replace(" ", ""))
    if dense == 0 or covered / dense < MIN_COVERAGE:
        return None
    # Only after the thresholds have passed, so scavenging inside a quote can
    # never promote prose into an "event" — the control stays on the outer line.
    _merge_nested(pairs, payloads)
    return pairs


def _merge_nested(pairs: dict[str, str], payloads: list[str]) -> None:
    """Merge the pairs inside auditd's nested quoted payload, first-wins.

    A real auditd ``USER_AUTH``/``USER_CMD``/``CRED_*`` record puts everything
    an analyst needs inside a second, single-quoted ``msg``::

        type=USER_AUTH msg=audit(…): pid=1 uid=0 auid=4294967295
            msg='op=PAM:authentication acct="svc-deploy" addr=203.0.113.9 res=failed'

    The pattern matches that whole span as one value, so ``finditer`` resumes
    *after* it and ``acct``/``addr``/``res`` were never produced as keys. The
    record then reached the auditd parser with only ``type/msg/pid/uid/auid/ses``,
    so ``user`` fell back to ``auid`` — ``4294967295``, the unset sentinel every
    pre-auth sshd record carries — with no address, no result, and no
    observables, while still being stamped ``structured`` with no note. The
    numeric user is not host-joinable, so the event carried **zero** joinable
    entity references and could never enter an incident: a brute force collected
    from ``audit.log`` produced zero incidents. Verified A/B through the real
    CLIs — identical records with the fields at the top level produced one
    score-30 incident, the nested form produced none.

    Depth is fixed at one, which is all auditd uses, so this cannot recurse.
    **Only the single-quoted value of a repeated ``msg`` is re-scanned** —
    auditd's shape, ``msg=audit(…): … msg='…'``. The first version re-scanned
    *every* quoted value containing ``=``, and review measured what that
    synthesized: ``type=USER_LOGIN user="msg=audit(1.0:1)"`` gained a ``msg``
    whose head is a clock stamp, ``msg="login failed comm=sshd
    timestamp=1.0"`` gained ``comm`` and ``timestamp``, and ``level=warn
    user="type=PATH msg=audit(1.0:1)"`` gained both ``type`` and ``msg`` —
    each then claimed as auditd, ``structured``, dated from the
    application's own field. A
    bare value is never re-scanned either: it cannot hold a space, and mining
    it would find ``a``/``b`` in ``url=http://h/?a=1&b=2``.

    **The residual, stated.** The rule is on the line's shape, so a line that
    itself carries a second, single-quoted ``msg`` is re-scanned whoever wrote
    it. Producing one takes control of the line's *structure*, and that
    control can already write the same keys at top level, which first-wins
    ranks above anything nested — so nesting adds nothing to it. Note what
    gives that control away: a quote the application did not escape, and also
    one it *did* escape logfmt-style — see :func:`decode`.

    First-occurrence-wins holds across levels too: a top-level key is never
    overwritten by a nested one, so a payload an attacker influences cannot
    restate the ``type`` or ``exe`` the head of the record already declared.
    """
    for payload in payloads:
        for match in _PAIR.finditer(payload):
            if len(pairs) >= MAX_PAIRS:
                return
            key = match.group("key")
            if key in pairs:
                continue
            value = match.group("dq")
            if value is None:
                value = match.group("sq")
            if value is None:
                value = match.group("bare") or ""
            pairs[key] = value[:MAX_VALUE_LEN]
