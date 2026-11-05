# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Detect a moved image tag behind a SHA-pinned Docker GitHub Action.

**The gap this closes, and the gap it does not.** `AGENTS.md` §5.1 records every
third-party action in ``security/third-party-actions.json``, and #320 added an
``execution`` block that derives whether this repository's 40-hex ``uses:`` pin
fixes the code that will actually run. For a composite action it does (the steps
are in the file) and for a node action it does (the ``dist/`` bundle is in the
vendor's tree at that commit). For a **Docker** action it may not: the pin fixes
``action.yml``, and ``action.yml`` names an image.

Measured 2026-11-05, ``ossf/scorecard-action`` at the commit this repository
pins declares::

    runs:
      using: "docker"
      image: "docker://ghcr.io/ossf/scorecard-action:v2.5.0"

``v2.5.0`` is a **mutable tag**. Whoever can push it in ``ghcr.io/ossf`` chooses
the container this repository executes, and nothing already here can see that
happen: the ``uses:`` SHA does not change, so Dependabot never opens a pull
request, and ``tests/security/test_workflow_permissions.py`` sees a correctly
pinned action because it is one.

This module makes the move **detectable**. It re-resolves each tag from the
registry and compares the answer with a digest committed beside the record. It
does **not** make the move impossible — only referencing the image by digest
does that, which is upstream's to do — so the record keeps
``pinned_by_sha: false`` and keeps its ``pin_gap``. Detection is the weaker
property and is named as the weaker property.

**Why it cannot be a step inside the job it protects.** Measured from the
runner's own source (``actions/runner``, ``ActionManager.PrepareRepositoryActionAsync``):
a Docker action's image is collected into ``state.ImagesToPull`` and pulled by
``PullActionContainerAsync`` during job *preparation*, before any step executes.
A check running as an earlier step in the same job therefore reports on an image
that has already been pulled. To gate rather than observe, the check runs as its
own job and the protected job declares ``needs:`` on it.

**Fail-closed, and the two failures are distinguished.** A moved tag exits 1; an
inability to determine the answer — a registry outage, a malformed response, an
undeclared registry — exits 2. They are different events and a gate that
conflated them would teach an operator to ignore the one that matters. Both stop
the dependent job, because a check that cannot answer must not report success.

Exit codes: ``0`` every checked reference matches · ``1`` a tag has moved ·
``2`` could not determine, or the record is malformed.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, NamedTuple

_REPO = Path(__file__).resolve().parents[1]
_RECORD = _REPO / "security" / "third-party-actions.json"

#: Registries this script is willing to contact. **Declared, never discovered** —
#: the same control `collect/` applies to log sources and `agents/policies/egress.py`
#: applies to hosts. A record naming any other registry exits 2 rather than
#: reaching out, so adding one is a reviewed code change and not a data edit.
_ALLOWED_REGISTRIES = frozenset({"ghcr.io"})

#: ``sha256:`` + 64 lowercase hex. The registry's answer is validated against
#: this before it is compared, so a proxy or a malformed response cannot satisfy
#: the comparison with something that is not a digest.
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

#: A repository path component: lowercase per the OCI spec, with separators.
#: Deliberately narrow — a reference that does not match exits 2.
_REPO_PATH = re.compile(
    r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$"
)

#: A tag: the OCI spec's allowed characters, bounded.
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")

#: Manifest media types to accept. A tag may resolve to a single-architecture
#: manifest or to an index; both carry ``Docker-Content-Digest``, and asking for
#: only one of them would make the other look like a failure.
_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)

_TIMEOUT = 20.0

#: Bound on a token response. A token is a few kilobytes; the ceiling exists so
#: a hostile or broken endpoint cannot stream indefinitely into memory.
_MAX_TOKEN_BYTES = 64 * 1024


class ImageRef(NamedTuple):
    """A parsed ``docker://`` reference from an action's ``image:`` value."""

    registry: str
    repository: str
    tag: str


class Determination(NamedTuple):
    """One record's outcome. ``moved`` and ``undetermined`` are not the same."""

    action: str
    reference: str
    expected: str
    observed: str | None
    moved: bool
    undetermined: bool
    detail: str


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Treat any redirect as a failure.

    Matching ``agents/tools/llm.py``'s opener. A manifest read is not supposed
    to redirect — only blob reads are — so a redirect here means the request is
    being steered somewhere the allow-list above never approved, and following
    it would resolve a digest from a host nobody declared.
    """

    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


def parse_image_reference(image: str) -> ImageRef | None:
    """Parse a ``docker://host/repo:tag`` value, or return ``None``.

    ``None`` means "nothing to check here", for the two cases that are not
    defects: a value that is not a ``docker://`` reference at all (a Dockerfile
    path, built from the tree the SHA already pins) and a reference that is
    already pinned by ``@sha256:`` (there is no tag to move).

    Anything that *is* a tag reference but cannot be parsed raises, because a
    reference this script cannot read is a reference it cannot check, and
    silently skipping it would be the vacuous-guard failure `AGENTS.md` names.
    """
    value = image.strip()
    if not value.startswith("docker://"):
        return None
    rest = value[len("docker://") :]
    if "@" in rest:
        return None  # already digest-pinned; no tag to move

    host, _, path = rest.partition("/")
    if not path:
        raise ValueError(f"reference names no repository: {image!r}")
    if ":" in host:
        raise ValueError(f"a registry port is not supported, declare one without it: {host!r}")

    repository, sep, tag = path.rpartition(":")
    if not sep:
        # No tag at all means the registry's implicit ``latest`` — which is the
        # most mutable reference there is, so it is checked, not waved through.
        repository, tag = path, "latest"
    if not _REPO_PATH.match(repository):
        raise ValueError(f"repository path is not a valid OCI name: {repository!r}")
    if not _TAG.match(tag):
        raise ValueError(f"tag is not a valid OCI tag: {tag!r}")
    return ImageRef(registry=host, repository=repository, tag=tag)


def _open(request: urllib.request.Request) -> http.client.HTTPResponse:
    """Send ``request`` through an opener that follows no redirect."""
    opener = urllib.request.build_opener(_RefuseRedirects())
    return opener.open(request, timeout=_TIMEOUT)  # type: ignore[no-any-return]


def _registry_token(ref: ImageRef) -> str:
    """Fetch an anonymous pull token.

    GHCR requires a bearer token even for a public repository. No credential of
    this repository's is sent: the request is anonymous, and the scope asks for
    ``pull`` on one named repository.
    """
    url = (
        f"https://{ref.registry}/token"
        f"?scope=repository:{ref.repository}:pull&service={ref.registry}"
    )
    # No suppression here deliberately: measured, neither ruff S310 nor bandit B310
    # fires on `opener.open(request)` (both target `urllib.request.urlopen`), so a
    # `# nosec` would imply a finding that does not exist. What makes the URL safe is
    # above: the scheme is a literal https, and the host was checked against
    # _ALLOWED_REGISTRIES before this is reached.
    request = urllib.request.Request(url, method="GET")
    with _open(request) as response:
        payload = json.loads(response.read(_MAX_TOKEN_BYTES).decode("utf-8"))
    token = payload.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError(f"{ref.registry} returned no token")
    return token


def resolve_digest(ref: ImageRef) -> str:
    """Return the digest ``ref.tag`` currently resolves to, validated.

    Raises on anything that is not a well-formed digest, so an outage or a
    rewritten response cannot be mistaken for agreement.
    """
    if ref.registry not in _ALLOWED_REGISTRIES:
        raise ValueError(
            f"registry {ref.registry!r} is not declared in this script's allow-list "
            f"({sorted(_ALLOWED_REGISTRIES)}); adding one is a reviewed code change"
        )
    token = _registry_token(ref)
    url = f"https://{ref.registry}/v2/{ref.repository}/manifests/{ref.tag}"
    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"Authorization": f"Bearer {token}", "Accept": _ACCEPT},
    )
    with _open(request) as response:
        digest = response.headers.get("Docker-Content-Digest", "")
    if not _DIGEST.match(digest):
        raise ValueError(f"{url} returned no usable Docker-Content-Digest (got {digest!r})")
    return digest


def docker_records(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Every record whose action executes as a Docker container."""
    return [
        entry
        for entry in record["actions"]
        if isinstance(entry.get("execution"), dict)
        and str(entry["execution"].get("using")) == "docker"
    ]


def check(record: dict[str, Any], *, offline: bool) -> list[Determination]:
    """Compare each tag-referenced Docker record against the registry.

    With ``offline`` the registry is not contacted and only the record itself is
    validated — that every tag-referenced Docker entry carries a committed
    ``image_digest`` in the right shape. That form is an ordinary offline drift
    gate and runs with the rest of §7; the networked form runs in CI.
    """
    out: list[Determination] = []
    for entry in docker_records(record):
        action = str(entry["action"])
        execution = entry["execution"]
        image = str(execution.get("entrypoint", ""))
        try:
            ref = parse_image_reference(image)
        except ValueError as exc:
            out.append(
                Determination(action, image, "", None, False, True, f"unparseable reference: {exc}")
            )
            continue
        if ref is None:
            continue  # a Dockerfile path, or already digest-pinned

        expected = str(execution.get("image_digest", ""))
        if not _DIGEST.match(expected):
            out.append(
                Determination(
                    action,
                    image,
                    expected,
                    None,
                    False,
                    True,
                    "execution.image_digest is missing or malformed; a tag-referenced Docker "
                    "action must commit the digest its tag resolved to, or nothing can tell "
                    "that the tag has moved",
                )
            )
            continue
        if offline:
            out.append(Determination(action, image, expected, None, False, False, "declared"))
            continue

        try:
            observed = resolve_digest(ref)
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
            out.append(
                Determination(
                    action, image, expected, None, False, True, f"could not resolve: {exc}"
                )
            )
            continue
        out.append(
            Determination(
                action,
                image,
                expected,
                observed,
                observed != expected,
                False,
                "matches" if observed == expected else "TAG MOVED",
            )
        )
    return out


def _load() -> dict[str, Any]:
    data = json.loads(_RECORD.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("actions"), list):
        raise ValueError(f"{_RECORD} does not hold an 'actions' list")
    return data


def main(argv: list[str] | None = None) -> int:
    """Entry point. See the module docstring for the exit codes."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="validate the record only; do not contact any registry",
    )
    args = parser.parse_args(argv)

    try:
        record = _load()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    results = check(record, offline=args.offline)
    if not results:
        # Not a pass: a guard over zero references proves nothing, and the only
        # honest answer is that there was nothing to check.
        print("no tag-referenced Docker action in the record; nothing to check")
        return 0

    for item in results:
        mark = "MOVED" if item.moved else ("?" if item.undetermined else "ok")
        print(f"[{mark:>5}] {item.action}: {item.reference}")
        print(f"         expected {item.expected or '(none)'}")
        if item.observed is not None:
            print(f"         observed {item.observed}")
        if item.moved or item.undetermined:
            print(f"         {item.detail}")

    moved = [item for item in results if item.moved]
    undetermined = [item for item in results if item.undetermined]
    if moved:
        print(
            "\nA pinned image tag now resolves to a different digest. This is a human "
            "decision point, not a bump: read what upstream republished, then update "
            "execution.image_digest in security/third-party-actions.json if it is "
            "legitimate.",
            file=sys.stderr,
        )
        return 1
    if undetermined:
        print(
            "\nCould not determine whether the tag moved. This is NOT a pass: a gate that "
            "cannot answer must not report success.",
            file=sys.stderr,
        )
        return 2
    if args.offline:
        # Say what was actually checked. Claiming the digests "still resolve"
        # when no registry was contacted would be the overclaim this whole
        # mechanism exists to prevent, one level up.
        print(
            f"\nOK (offline): {len(results)} tag-referenced image(s) each carry a committed "
            "digest. Nothing was resolved, so this says the record is complete, not that the "
            "tags have not moved."
        )
        return 0
    print(f"\nOK: {len(results)} tag-referenced image(s) still resolve to the committed digest")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
