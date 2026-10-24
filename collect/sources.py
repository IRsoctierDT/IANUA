# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Which files this node is allowed to read — the boundary stage 5 crosses.

Every other package keeps its filesystem reach inside the project and the
gitignored lab-data root. This one deliberately reaches *out*, to the node's
own logs, which is the §5 boundary the owner approved for stage 5. Reaching
out is the whole point of a collector, so the control is not "stay inside" but
"read only what was explicitly declared, and only if it is shaped like a log".

Security considerations (AGENTS.md §3, §5):

* **Declared, never discovered.** There is no glob, no directory walk and no
  "find the logs" heuristic. An operator names each file. A collector that
  searched for sources would eventually find one nobody meant it to read, and
  the blast radius of that mistake is fabricated evidence in the store.
* **Absolute paths only.** A relative path means whatever the scheduler's
  working directory happens to be, and cron's is not the one an operator
  tested in.
* **The final component may not be a symlink.** This is a deliberately
  *narrower* rule than ``store.paths.confine`` applies to the lab-data root,
  and the asymmetry is reasoned rather than sloppy: under the lab root every
  component is ours and a link anywhere is an escape, whereas ``/var/log`` is
  a system path whose ancestors are legitimately symlinks on several
  distributions. Refusing those would refuse the normal case. Refusing a link
  at the *file* catches the move that redirects a reader at a chosen target
  without needing write access to the real log.
* **Credential-bearing paths are refused outright.** A collector faithfully
  turns whatever it reads into stored events, so pointing it at a private key
  would copy that key into ``data/`` — §5 names credentials sensitive by
  default, and "the operator asked for it" is not a reason to help. The
  deny-list below is not a complete defence (nothing pattern-based is) and is
  not presented as one; it stops the plausible accident.
* **Read-only, always.** Sources are opened ``"rb"`` and nothing in this
  package writes to one. A security test asserts no write mode reaches a
  source path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from collect.errors import SourceError

#: Paths and names that almost certainly hold a secret rather than a log.
#: Matched against the whole resolved path, case-insensitively.
#:
#: Deliberately conservative: each entry is something whose presence in an
#: event store would be a credential leak, not merely noise. A broader list
#: would start refusing real logs, and a collector that refuses real logs gets
#: switched off.
_DENIED = re.compile(
    r"(?:"
    r"/etc/(?:shadow|gshadow|sudoers)"
    r"|/\.ssh/"
    r"|/\.aws/credentials"
    r"|/\.gnupg/"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)$"
    r"|\.(?:pem|key|pfx|p12|jks|keystore)$"
    r"|/\.env$"
    r"|/\.netrc$"
    r"|/\.pgpass$"
    r")",
    re.IGNORECASE,
)

#: Largest single line this collector will hand onward, in bytes. A line past
#: this is truncated and counted, never dropped: ``ingest/`` marks an
#: over-long record degraded, which is a visible outcome, whereas dropping it
#: is the silent loss this platform refuses.
MAX_LINE_BYTES = 64 * 1024

#: Most bytes read from one source in one invocation. A backlog is worked
#: through over several scheduled runs rather than in one unbounded read: the
#: offset advances every run, so progress is monotone, and a 10 GiB file
#: cannot turn a scheduled job into an out-of-memory kill.
MAX_BYTES_PER_RUN = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Source:
    """A validated, readable log file on this node.

    Constructing one is the only way to name a source, so every path that
    reaches the reader has been through :func:`declare`. ``key`` is the stable
    identity used in the offsets file — the resolved path, so two spellings of
    one file share a position instead of each re-reading it.
    """

    path: Path
    key: str

    @property
    def name(self) -> str:
        """Short label for reports and audit records."""
        return self.path.name


def declare(raw: str | Path) -> Source:
    """Validate one operator-declared log source.

    Raises:
        SourceError: if the path is relative, missing, not a regular file, a
            symlink at its final component, on the credential deny-list, or
            cannot be examined at all. Refused rather than skipped — see
            :class:`SourceError`.
    """
    path = Path(raw)
    if not path.is_absolute():
        raise SourceError(
            f"source {raw!r} is not absolute; a relative path means whatever the "
            "scheduler's working directory happens to be, which is not the one you "
            "tested in"
        )
    try:
        return _examine(path)
    except OSError as exc:
        # Through 3.13, `is_symlink()`, `exists()` and `is_file()` swallow
        # ENOENT, ENOTDIR, EBADF and ELOOP and return False, but not
        # ENAMETOOLONG or EACCES, which escaped as a bare `OSError` from the
        # first probe. Measured on 3.11, 3.12 and 3.13: a 5000-byte path and a
        # single 300-byte component each raised `[Errno 36] File name too
        # long`, and a log under a directory the collector's user may not
        # search raised `[Errno 13] Permission denied`. (On 3.14 those three
        # are `os.path` predicates that swallow every `OSError`, so both cases
        # are refused below as "does not exist": the right type, with a vaguer
        # reason.) The CLI catches `OSError` too, so its exit code was right by
        # accident; that is the gap `store.paths.validated_root` closed for
        # `--root`. Only the reason is quoted, because the OSError's own text
        # repeats the path, which for ENAMETOOLONG is the long part.
        raise SourceError(
            f"source {path} cannot be examined ({exc.strerror or type(exc).__name__}); "
            "declared sources are refused rather than skipped, because a source this "
            "collector cannot inspect is a blind spot nobody is told about"
        ) from exc


def _examine(path: Path) -> Source:
    """The filesystem half of :func:`declare`, for a path already known absolute.

    Every probe here can raise ``OSError``, and :func:`declare` refuses on it, so
    a declared path leaves as a :class:`Source` or a :class:`SourceError` and as
    nothing else.
    """
    # Checked before resolve(), so the refusal names what the operator typed
    # rather than wherever it happens to point.
    if path.is_symlink():
        raise SourceError(
            f"source {path} is a symlink (-> {path.readlink()}); refusing to follow it. "
            "A link at the log file redirects this reader at a chosen target without "
            "needing write access to the real log, and what it reads becomes stored "
            "evidence."
        )
    if not path.exists():
        raise SourceError(
            f"source {path} does not exist; declared sources are refused rather than "
            "skipped, because a source silently dropped is a blind spot nobody is "
            "told about"
        )
    if not path.is_file():
        raise SourceError(
            f"source {path} is not a regular file; directories, devices and FIFOs are "
            "not logs this collector knows how to position itself in"
        )
    resolved = path.resolve()
    # BOTH spellings are checked. The positional rules (``/.ssh/``,
    # ``/.gnupg/``) describe where a secret lives, and an ordinary symlinked
    # ancestor — ``/home/ivan`` pointing at ``/mnt/users/ivan`` — resolves them
    # away, so a resolved-path-only check let every positional rule be
    # bypassed without any symlink at the file itself. Found by review.
    if _DENIED.search(str(resolved)) or _DENIED.search(str(path)):
        raise SourceError(
            f"source {resolved} looks like a credential store, not a log. This "
            "collector copies whatever it reads into the event store, so collecting "
            "it would put a secret in data/ — AGENTS.md §5 treats credentials as "
            "sensitive by default."
        )
    return Source(path=path, key=str(resolved))


def declare_all(raws: tuple[str | Path, ...]) -> tuple[Source, ...]:
    """Validate every declared source, or raise on the first bad one.

    All-or-nothing on purpose. Collecting the valid subset and reporting the
    rest would start the run with a known blind spot, and the operator would
    see a successful exit code.

    **Collapsed by key**, keeping the first spelling of each file. Two names
    for one file — ``--source X --source X``, or a path and its symlinked
    parent's spelling — share one stored position, so a pass would read the
    same region twice from that one position, append both batches, and then
    report the pass against a result map that had collapsed to one entry: an
    audit record stating "read N line(s) from 1 of 2 source(s)" about a pass
    that read one file twice. The duplicate events are harmless because the
    store is content-addressed; the misstated record is in a hash-chained log
    and cannot be corrected afterwards. Found by review.

    Deduplicating here rather than in the CLI keeps it true for every caller,
    and happens *after* validation so a repeated bad path is still refused.
    """
    declared: dict[str, Source] = {}
    for raw in raws:
        source = declare(raw)
        declared.setdefault(source.key, source)
    return tuple(declared.values())
