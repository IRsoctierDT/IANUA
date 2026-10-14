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
  named constant and the excess is dropped with the record marked degraded by
  ``ingest/``'s existing machinery.
* **Pure.** No clock, no filesystem, no network, no subprocess, no ``eval``.
  The package's AST invariants already assert this and now cover this module.
* **Nothing is executed or resolved.** A value is text. ``comm=/bin/sh`` is a
  string that happens to look like a path, and this module does not care.
"""

from __future__ import annotations

import re

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

    Later keys win on a repeat, which is the convention every logfmt reader
    follows. auditd's repeated ``a0``/``a1`` argv keys are distinct names, so
    the EXECVE reassembly in ``parsers/endpoint.py`` is unaffected.

    Args:
        line: One decoded log line, newline already stripped.

    Returns:
        A mapping of at least :data:`MIN_PAIRS` pairs covering at least
        :data:`MIN_COVERAGE` of the line's non-space characters, or ``None``.
    """
    pairs: dict[str, str] = {}
    covered = 0
    for match in _PAIR.finditer(line):
        # Coverage is counted for every pair found, including those past the
        # cap. Stopping the scan instead would make a *denser* line look
        # sparser: a 1000-pair record would score coverage over only its first
        # MAX_PAIRS and be rejected as prose, which is the opposite of the
        # intent. The cap bounds what is *kept*, not what is *measured*.
        covered += len(match.group(0).replace(" ", ""))
        if len(pairs) >= MAX_PAIRS:
            continue
        key = match.group("key")
        value = match.group("dq")
        if value is None:
            value = match.group("sq")
        if value is None:
            value = match.group("bare") or ""
        pairs[key] = value[:MAX_VALUE_LEN]

    if len(pairs) < MIN_PAIRS:
        return None
    dense = len(line.replace(" ", ""))
    if dense == 0 or covered / dense < MIN_COVERAGE:
        return None
    return pairs
