# Changelog

All notable changes to this project. Versions correspond to git tags.

## Unreleased

### Added
- **Coverage-guided fuzzing with Atheris (`tests/fuzz/`, `.github/workflows/fuzz.yml`).** There
  are four targets, one for each surface that parses untrusted bytes: `ingest.normalize` on the
  bytes `collect/` feeds it, `ingest.keyvalue.decode`, the egress address and port checks, and
  `NormalizedEvent.from_dict`, the only reader of a stored projection. Each asserts what its
  module already documents, such as bounded output, determinism, the store's read-back round
  trip and the egress refusals. Each fails through an explicit `AssertionError`, so `-O` cannot
  disable it. CI fuzzes each target for one minute on a pull request or push that touches what it
  imports, and for ten minutes weekly. The job installs Atheris alone, hash-pinned from
  `requirements.lock`, and holds no write permission or secret.
  `tests/fuzz/test_fuzz_corpus.py` replays every seed through the same targets on every platform.
  It plants one violation per target to show the checks can fail, and pins four things: the
  runner's instrumentation, the CI matrix, the path filters against the targets' real import
  graph, and the platform marker. Measured with the workflow's own scripts over 60 seconds per
  target: 1.8M, 1.2M, 135k and 7.2M inputs, and no finding. A planted check fell inside the
  minute, exited 77, and left a reproducer that the documented command replays. OpenSSF
  Scorecard's Fuzzing check detects Python fuzzing by `import atheris`, which the runner has.
- **Atheris 3.1.0 is a new dependency, in a `[fuzz]` extra.** It is Apache-2.0 and maintained
  by Google. It ships manylinux x86_64 wheels for CPython 3.12 to 3.14 only and no sdist, so the
  extra carries a marker that keeps it off macOS, Windows and Python 3.11, where installing it
  would fail. It is not in `[dev]`, because the wheel is about 37 MB. `uv.lock`, the derived locks
  and the SBOM are regenerated: 136 Python components, and `pip-audit` reports none vulnerable.
  Dependabot groups it with the dev toolchain.

### Changed
- **An event's excerpt keeps non-ASCII text as written, so every indicator it yields is a
  substring of it. This changes `event_id` for any record with non-ASCII text in a modelled
  field.** `ingest/normalize.py` rendered `raw_excerpt` with `json.dumps`, whose default is
  `ensure_ascii=True`. An unclaimed record's indicator `https://café.example/x` was
  extracted as written and retained as `https://caf\u00e9.example/x`, so it was not in the
  evidence it came from. Each escaped character also spent six of the excerpt's 4,096
  characters, or twelve outside the BMP. Measured: a modelled field of 2,048 `é` kept 681
  of them and now keeps all 2,048. The excerpt and the leaf fragments it is searched for share
  one encoder, because with only the excerpt changed the search stopped at the first
  non-ASCII value and extracted no indicator in it or after it (measured). The store's
  `canonical_json` already kept Unicode as written, so the stored projection no longer holds
  the excerpt's escape escaped a second time. Format characters such as U+202E are written
  as themselves, as they already were in the typed fields, and are escaped where they are
  printed (`scripts/_terminal.printable`). The fuzz target's escaped-form allowance is gone.
  `tests/security/test_ingest_unicode.py` pins the rendering, the budget and the encoder
  pairing. **Action for operators:** the owner accepted the one-time id change instead of a
  `SCHEMA_VERSION` bump, which would make every existing store and backup refuse to open.
  Rows stored before this release stay readable and still verify. A restore
  (`docs/RESTORE.md` step 5) or a re-collection (`docs/RETENTION.md`) that re-reads a log
  line an earlier build stored stores it again if a modelled field holds non-ASCII text.
  Measured across the two builds: two lines re-read, the ASCII one deduplicated, the other
  stored a second time. ASCII-only events still deduplicate, a second re-read by this build
  stores nothing, and a line that has rotated out of its source cannot be re-read. The
  committed fixtures are all ASCII, so no committed id or digest changes (0 of 15 on either
  path). An unclaimed record's projection stays under the store's 64 KiB ceiling: about
  50 KiB at most by its per-field bounds, and 46,668 bytes on a record built to fill them.

### Security
- **`filelock` 4.2.4 and `setuptools` 84.2.1 close two advisories that turned `main` red.**
  CVE-2026-112940 (`filelock` 3.29.4, fixed in 4.2.1) and GHSA-xmj3-9gf7-h52w (`setuptools`
  83.0.0, fixed in 84.1.0) were published on 2026-10-23, after #292's checks passed and before
  its merge commit's CI ran. CI's `pip-audit` gate failed on that commit and on every pull
  request after it. Neither package is a direct dependency: `filelock` comes in through
  `cachecontrol`, `huggingface-hub`, `python-discovery`, `torch` and `virtualenv`, and
  `setuptools` through `torch`. `uv lock --upgrade-package` moved these two of 141 packages and
  nothing else. Both cross a major version, and no dependent caps either. The derived locks and
  the SBOM are regenerated. The build-system floor rises from `setuptools>=84.0.0` to
  `>=84.1.0`, because the old floor still admitted the vulnerable 84.0.0.
- **A log line carrying a JSON-escaped lone surrogate no longer stalls its collector source.**
  `json.loads` turns an escape such as `\ud800` into a lone surrogate, and `ingest`'s `text()`
  kept it. The store encodes each projection as UTF-8 before writing it, which refused it with a
  bare `UnicodeEncodeError`, and `scripts/run_collector.py` holds a source's offsets until its
  batch is durable. Measured on `2090519` under CPython 3.12.13 and 3.13.17: a three-line,
  all-ASCII log whose middle line carried a Defender `Subject` of `x \ud800 y` stored 0 of 3
  events on every pass, `offsets held`, exit 1, so no later line of that source was ever stored.
  An unclaimed record whose key name held the escape was refused the same way, because the
  withheld-field note names the key. `text()` now replaces every surrogate with U+FFFD, as the
  bytes path's `errors="replace"` already did, so the event is stored with the replacement
  visible and the source advances. Every typed field, key name, excerpt value and carried text
  passes through `text()`: a security test plants a surrogate at every string site of every
  committed fixture, on both paths and through both entry types, and none reaches the
  projection. The fuzz target now hashes the projection as the store does. It could not see this
  before, because `canonical_json` alone never encodes.

### Known issues
- **`tests/fuzz/targets.py` does not yet assert three documented contracts, because none of
  them holds today:** the event store's 64 KiB projection ceiling (`normalize` can build an
  event the store refuses, which stalls that source), the MCP transport's "malformed input
  never crashes the loop", and the documented error type of `EgressAllowlist.load`. Each
  needs its own fix. Keeping non-ASCII as written above moves a claimed record up to about
  12 KiB closer to that ceiling: measured with three-byte characters, the excerpt's share of
  the projection grew from 4,734 to 11,073 bytes.

## v2.3.1 — Immutable Releases & Gate Hardening — 2026-10-23

### Documentation
- **`docs/PROJECT_STATUS.md`'s Completed Milestones now run through v2.3.0.** They had stopped
  at v1.8.0, five releases back. Each new entry is drawn from that release's own section of
  this changelog. (#289)
- **Two `DESIGN.md` decision-log rows miscounted, and only one of them had the number wrong.**
  The 2026-10-16 SQL-injection row said "eleven rejected routes" and then named twelve. The
  test's `_REJECTED` table holds eleven, and `+=` lives in the separate multi-statement table,
  so the list was wrong. The active/passive HA row said six security test files assert
  `dependencies = []`. There are five, two of which also check the installed metadata, so the
  number was wrong. Both are corrected in place with a note. (#288)

### Fixed
- **Four places still said a restored pipeline cursor ahead of the store is safe, and it is
  not after a backward clock step.** `next_stamp` compares the clock against the store's
  high-water mark and never against the cursor, so once the clock is below a restored cursor,
  new events are stamped under it and the detection cycle never reads them. Measured: a store
  at mark T, a cursor at T+3600 and a clock at T+60 stamp the next event T+60, and
  `run_cycle` reads 0 of the 2 stored events, or both with no cursor. #210's review corrected
  `docs/RESTORE.md`'s table but not `scripts/run_backup.py`'s docstring ("ahead of it merely
  idles"), the sentence above the table ("exactly one is unrecoverable"), the 2026-10-15
  `DESIGN.md` row, or `tests/integration/test_restore_drill.py`'s "the one unrecoverable skew"
  docstring. All four now say two of the four directions are unrecoverable. A new drill test
  pins the measurement, so the four have to change together if `next_stamp` ever does.
  Backups already left out the cursor, and `docs/RESTORE.md` step 3 already deletes it, so
  behaviour is unchanged. (#284)
- **The pre-commit hooks for ruff, mypy, bandit and detect-secrets now run the locked toolchain
  rather than pins of their own.** As hosted hook repos, three of them had drifted from
  `uv.lock`: ruff v0.6.9 against 0.17.1, mypy v1.11.2 against 2.4.0, and bandit 1.7.10 against
  1.9.4. All four ran in pre-commit's isolated environments, which never saw the project's
  dependencies. They are now `repo: local`, `language: system` hooks run as `python -m <tool>`
  from the environment `pip install -e ".[dev]"` sets up, so a commit needs that environment
  active. Every hook passed over the whole tree, and one planted violation per tool failed its
  hook. `tests/unit/test_gate_scope_parity.py` pins the shape, so there is no second version to
  keep in step. This closes `docs/PATH_RECONCILIATION_AUDIT.md` stage 1.2 (G2), differently from
  the bump it prescribed. (#285)

### Security
- **Releases are immutable from 2026-10-23, and `release.yml` no longer uploads to one that
  is.** The owner enabled GitHub's release immutability, so a release published from that date
  locks its tag and assets when it is published. v2.3.0 and earlier stay mutable. The normal
  flow is unaffected, because `gh release create` attaches every asset to a draft before it
  publishes. The repair step used to run `gh release upload --clobber` against any published
  release. It now reads `isImmutable` first: on `false` it repairs as before, on `true` it only
  checks that every asset is attached and names any that is missing, and on anything else it
  fails. A release published from the web page locks with no assets; the job now fails and
  names each missing asset, and the remedy is the next patch version. `docs/RELEASING.md` now
  says never to publish from the web page and documents `gh release verify`.
  `tests/security/test_release_immutability.py` runs the step's own script against a stand-in
  `gh`. (#283)
- **CFG-02 now passes IP literals only: a dashboard bound to `localhost` fails it.** The
  control's allow-list was `("127.0.0.1", "::1", "localhost")`, and its comment called
  that "the two loopback forms". `localhost` is a name, so it binds whatever the host's
  resolver maps it to. The check reads the config and never resolves, so it cannot vouch for
  one. Measured on one container, `localhost` resolved to `127.0.0.1` alone. The owner chose
  to refuse it, which applies AGENTS.md §5's IP-literals-only rule for declared egress hosts
  to the dashboard's bind. A name now fails with its own message, "a name rather than an
  address". The committed config binds `127.0.0.1` and still passes. **Action for operators:**
  a deployment whose `.streamlit/config.toml` sets `address = "localhost"` now fails CFG-02,
  so set `127.0.0.1` or `::1`. (#286, #287)
- **A file named like an option no longer turns the pre-commit secret scan into a pass.**
  pre-commit appends the staged filenames after a hook's `args`, and the detect-secrets hook's
  `args` did not end with `--`. Measured in a throwaway repository: a file named `--help`
  staged beside a private key made the hook print its usage, and pre-commit reported **Passed**
  at exit 0. That is AGENTS.md §7.1's dash-led-filename hazard, on the pre-commit path rather
  than the `xargs` one. The ruff, ruff-format, mypy and detect-secrets hooks now end their
  `args` with `--`. Before the change ruff and mypy already failed, but with an argument error
  and without checking the code. A new security test in `tests/security/test_secret_gate.py`
  rebuilds pre-commit's own argv from the committed config and requires the key to be found.
  A parity test requires the terminator on every local hook that receives filenames. (#290)

### Known issues
- **`--help` still raises `UnicodeEncodeError` on an ASCII-only stdout in fourteen CLIs under
  `scripts/`, as in v2.3.0.** Re-measured for this release with `PYTHONIOENCODING=ascii`:
  fourteen exit 1 on a non-ASCII character in their help text (U+2014, or U+00A7 in
  `secret_gate.py`). A UTF-8 locale or `PYTHONIOENCODING=utf-8` works around it (measured on
  `scripts/run_retention.py`: exit 0). Two more CLIs fail `--help` for a different reason: an
  optional dependency that is not installed (`weasyprint`, `qdrant_client`).

## v2.3.0 — Production SOC Foundations — 2026-10-23

### Added
- **`store/` is a durable, append-only event store, stage 1 of the production-SOC program.** It
  uses stdlib `sqlite3` under gitignored `data/events/`, so `dependencies = []` stands. SQLite
  triggers raise on `UPDATE`, and each row is keyed by the SHA-256 of its canonical projection,
  so a re-read event is stored once and a row edited outside the platform raises
  `StoreIntegrityError` on read. `EventStore.query` takes a fixed set of `Query` pivots (time,
  source, vendor, user, host, IP, observable) and returns at most 10,000 rows.
  `docs/PRODUCTION_SOC_PLAN.md` records all nine stages. (#198)
- **`correlation/` resolves entities across telemetry domains and assembles incidents, stage
  2.** References merge only on declared exact rules, never fuzzy ones: co-occurrence within one
  event's actor or device, exact normalized equality, and a user principal whose local part
  matches a bare username. The two ends of a connection never merge, nor does an address with a
  host, and built-in principals such as uid `0` and display names never join. An entity in more
  events than `Thresholds.max_entity_fanout` (default 50) is reported as context rather than
  used to join. Every score contribution is recorded in `incident.reasons`. (#199)
- **Audit records can name who asked: `agents.policies.Principal` is a caller identity carried
  in the hashed `actor` field, stage 3.** It renders as `component` or `component/caller`, and a
  component-only principal is byte-identical to the string `actor` held before, so the schema is
  unchanged. Nothing authenticates it. The hash preimage joined fields with an unescaped `|`, so
  a value containing `|` could make a deny record hash like an allow record.
  `AuditLogger.record` now refuses `|` in `actor`, `action`, `action_class`, `decision` and
  `reason`, and containment percent-encodes the target and detail it records. (#201)
- **`scripts/run_pipeline.py` runs one detection cycle per invocation, for cron or a systemd
  timer (stage 4).** A cycle reads the events after a stored `(ingested_at, event_id)` cursor
  and correlates them with a trailing `--lookback` (default 900 s) of already-read history, so
  an attack spread over several cycles within it is still assembled. The cursor advances only
  after the cycle and its audit record succeed, so a crash re-reads a window rather than
  skipping it. Cycles are gated `read_only` by the policy bundle, hold an exclusive lock, and
  record a caller only from `--caller`. (#202)
- **`scripts/run_collector.py` reads this node's own log files into the event store, stage 5 and
  the first `AGENTS.md` §5 boundary crossing.** Each `--source` is an absolute path the operator
  names: there is no glob or directory walk, and a symlinked log, a non-regular file or a path
  on the credential deny-list is refused. Sources are opened read-only, a first run reads from
  the beginning, and rotation and truncation in place are detected on resume. The new
  `ingest/keyvalue.py` decodes auditd `key=value` lines into a mapping the existing auditd
  signature claims. Collection is its own `collection` policy class, `allow` by default. (#204)
- **`scripts/run_retention.py` gives `EventStore.prune` a caller: it reports by default and
  deletes only on a grant.** A dry run is gated `read_only` and deletes nothing. `--apply` is
  gated `destructive`, which the shipped bundle sets to `require_approval`, so it exits `3`
  until an operator adds `retain_events:apply` to the bundle's `allow` list; a grant of the bare
  `retain_events` does not match. The window is `--keep-days` (default 90), keyed on
  `ingested_at`. A pruned event is not re-collected on a later pass, because the collector's
  offsets are never rewound. (#208)
- **`scripts/run_backup.py` takes a verifiable copy of the lab-data state, and `docs/RESTORE.md`
  is the restore procedure.** The store is copied through SQLite's online backup API: a copy of
  the main file alone, taken while a writer held the store, opened cleanly and reported 353 of
  400 events. The new `EventStore.attest()` digests every `event_id` with the row count, and
  `--verify` checks a backup against the manifest that carries it. Collector offsets and the
  pipeline cursor are never backed up, and the runbook deletes both before the store is
  restored. `store.append` now also refuses an event `query` could not read back. (#210)
- **`sli/` and `scripts/report_sli.py` measure the platform's own service level, fail-closed.**
  Eight objectives, from `collection-pending` to `backup-present`, grade `met`, `breached`, or
  `unknown` when a signal cannot be read, and the report exits `1` if any is breached or
  unknown. It opens nothing outside the lab-data root and creates nothing. Retention now stops
  at the pipeline cursor, and deleting unprocessed events takes `--include-unprocessed` under a
  separate `retain_events:apply-unprocessed` grant. A log line holding a 5000-digit integer
  stalled its collector source on every run; it is now stored as `unrecognized`. (#217)
- **GitHub Releases now publish the curated changelog section as their body.** `release.yml`
  used `--generate-notes`, which lists merged pull requests, so a release's own section of
  `docs/Changelog.md` was never published. The new `scripts/release_notes.py` composes the body
  from that section verbatim plus a compare link to the previous release, and a missing,
  duplicated or empty section fails the job rather than publishing blank notes.
  `scripts/prepare_release.py` now prints an `ACTION NEEDED` notice on stderr for the
  `docs/PROJECT_STATUS.md` prose a version bump leaves describing the previous release. (#193)
- **Every tracked `.py` file carries an SPDX licence notice, and generated artifacts state their
  origin.** The licence stays Apache-2.0; 249 tracked `.py` files gain `SPDX-FileCopyrightText`
  and `SPDX-License-Identifier` lines, placed after any shebang. Incident reports gain a
  provenance footer (version from `agents.__version__`, repository URL, licence, `NOTICE`
  pointer), and `docs/status.html` and `docs/trust.html` gain attribution from their builders.
  `tests/unit/test_attribution.py` fails the build on a new `.py` file without a notice.
  `docs/IP_AND_LICENSING.md` §3.1.1 records why. (#200)
- **`docs/RETENTION.md` is the retention runbook that four files already cited and none could
  resolve.** It records that a prune returns no disk: a 20,889,600-byte store reported
  `events_removed: 10200` of 12000 and was 20,889,600 bytes afterwards, because a `DELETE` frees
  pages for reuse without shrinking the file. It documents the manual `VACUUM` that does return
  bytes, that a dry run does not predict the `--apply` after it, and that `report_sli.py` cannot
  see a prune. `tests/unit/test_docs_runbooks.py` checks that every `docs/*.md` reference in the
  five citing files exists. (#220)
- **`DESIGN.md` §11 records the approved active/passive HA decision before any replication code
  exists.** `dependencies = []` stands: the consistency point is `sqlite3.Connection.backup`,
  and transport is left to the operator. It crosses two charter boundaries instead: egress to a
  declared peer, and an inbound listener. The platform has no fence: `flock` keys on an inode,
  so two roots each acquire the single-instance lock, which
  `tests/security/test_ha_fence_is_local.py` pins. The one fence today's charter allows is
  procedural, the operator stopping the former active node's timers. (#229)
- **`scripts/secret_gate.py` runs §7.1's secret gate end to end, including the re-scan
  after staging.** The documented procedure for a baseline refresh ended at "verify, then
  stage"; verifying proves the rewrite was a refresh and says nothing about whether the
  gate then passes (the owner's point). The script invokes the hook without `xargs` —
  through it a finding's exit 1 and a refresh's exit 3 both surface as 123 — refuses up
  front what the hook misreports or runs over silently (a root that is not the repository
  top level; a baseline that is missing, a symlink, untracked, unparseable, or carrying
  unstaged edits — a staged edit is the ACCEPT procedure's own state and is gated), verifies
  that a rewrite is a refresh, stages only that file, requires the post-staging re-scan to
  exit 0, and on every other path restores the pre-run bytes and index entry. **One charter
  claim fell while building it:** §7.1 said the hook's exit-3 rewrite "only ever moves a
  line number". Measured, deleting an accepted literal exits 3 with the same message and
  *retires* the entry, so a refresh is "move or retire" and the first version of the script
  refused a retirement as an acceptance. A retirement cannot hide a relocation — a literal
  moved to another tracked file is a new finding there, exit 1, and the refresh is
  suppressed (measured). An independent four-lens review of the first commit then found the
  symlink, untracked, unparseable, sub-directory and staged-then-failed cases, and Codex's
  review of #242 found three more — a credential staged and then removed by an unstaged
  edit scanned clean while the index still held it (the gate now refuses any tracked file
  with unstaged changes: the hook scans the work tree, a commit records the index), a
  hard-linked baseline the hook would rewrite through the shared inode, and a nonexistent
  `--root` that exited with a traceback — each reproduced before it was fixed. `tests/security/test_secret_gate.py` pins every branch
  in throwaway repositories with the real hook, drives the outcomes it cannot produce on
  demand with a stand-in named as such, and its last test requires this repository's
  committed baseline to pass the hook at exit 0 on every run (the hook's full run over the
  tree, 41 s here; a gate that is not run is a claim).
- **"Lab host" is now defined, and the definition is a committed, empty allow-list.**
  `AGENTS.md` §5 forbade "sending network requests to non-lab hosts" and §5.1 gated
  "requests to any non-lab host" — and nothing said what a lab host *was*, so the term
  the whole egress permission rests on was enforced by whoever was reading it.
  `agents/policies/egress.py` answers it declaratively, because **no property of an
  address can**: RFC1918 is not a proxy for "lab", a routable address is not a
  disqualifier, and reverse DNS is whatever the other side says. A lab host is one named
  in `agents/policies/egress.json` with its authorization basis recorded beside it, and
  the file ships **empty**, so every destination is denied today. This is `collect/`'s
  control with one word changed: declared, never discovered.
  **No network code ships.** The module answers one question — is this destination
  declared? — and a `tests/security` case AST-asserts it imports no `socket`, `ssl`,
  `http`, `urllib` or `subprocess`, because the definition of a boundary must not also
  be a way across it. First of the three pieces the stage 7 amendment ordered
  (allow-list, then listener, then puller).
  **IP literals only**, which is the SSRF decision rather than a formatting rule: a
  hostname resolves at connect time, so the file would name a name while the socket goes
  wherever resolution answers. Refused on the **parsed** value — unspecified in any of
  its six spellings, multicast, limited-broadcast, link-local
  (`169.254.169.254` is the cloud metadata address), IPv4-mapped and scoped IPv6 forms
  (they alias: `::ffff:127.0.0.1 != 127.0.0.1`), duplicates after normalization, and an
  entry with no authorization basis. Also refused: a non-string address, because
  `ip_address` accepts integers and `bool` is an `int` subclass — `{"address":
  3232235777}` would have loaded as `192.168.1.1`, a destination no reviewer can see in
  a diff. **Loopback and routable addresses are declarable deliberately**; a control
  that cannot be exercised is one an operator switches off.
  Declaring a peer turns a `tests/security` test red on purpose: an edit to the egress
  allow-list should not pass review unnoticed.
- **`run_backup --verify-restore BACKUP`, the promotion gate.** `--verify` checked
  a backup against its own manifest *before* a restore; `docs/RESTORE.md` step 4
  then copied it into place with `cp -a` and nothing looked at the result. A
  store missing most of its pages opens cleanly and reports a plausible count
  (353 of 400, measured), so a half-finished copy left a working SOC quietly
  short of evidence. The new mode re-attests the **live** root and requires the
  manifest's digest and event count, reports `LOSS`/`SUBSTITUTED`/`ADDED`/
  `TRUNCATED`/`REWRITTEN`/`POSITION PRESENT` so the direction is never
  ambiguous, and states on success that it verifies the *copy* and says nothing
  about whether exactly one node is active. Run it between steps 4 and 5.
- **OpenSSF Scorecard runs as a workflow, with its egress off and every action
  SHA-pinned** (`.github/workflows/scorecard.yml`) — which is where Scorecard's
  own installation instructions put it. It grades the posture this repository
  already claims in §3 and §8 — actions pinned by SHA, least-privilege workflow
  tokens, dangerous-pattern detection, automated dependency updates, a SAST tool
  — by a third party instead of by us, reporting into this repo's Code scanning
  tab and as a run artifact.
  **`publish_results: false`, deliberately.** True would POST results to the
  OpenSSF REST API at `https://api.scorecard.dev` and enable a public badge —
  outbound egress of repository metadata, which §5.1 classes as an
  external-network action needing human approval with the URL shown in full. The
  owner was shown it and chose `false`. `id-token: write` is absent for the same
  reason — it exists only to sign *published* results — and the job holds exactly
  one write, `security-events`, to upload the SARIF.
  `tests/security/test_scorecard_boundary.py` asserts all of it, so turning
  publishing on is a deliberate edit that fails a test until that §5.1 decision
  is revisited.
  **What that choice does not buy, since the first draft of this entry claimed
  more than it should.** IANUA is a **public** repository, and the pinned
  action's own README states that the Scorecard team scans public repositories
  weekly and publishes those results regardless, with `publish_results: true`
  merely *replacing* them with our own run's. So `false` means **this run is not
  submitted to OpenSSF** — not "results are private", and not "no entry in the
  public OpenSSF dataset", both of which this entry said and neither of which is
  true. What is given up is the badge and having the public entry come from our
  run rather than theirs. The same README notes the SARIF run artifact is
  "available to anybody for five days after the run", so the `retention-days: 5`
  upload is not a private channel either; it is the owner's choice (Code scanning
  *and* the Actions tab) and it stays, now recorded accurately.
  The endpoint was wrong too, in all four places it appeared: this entry, the
  workflow header and twice in the security test. `api.securityscorecards.dev`
  was written from memory; `https://api.scorecard.dev` is the pinned action's own
  `internal_publish_base_url` default, read out of `action.yaml` at the exact SHA
  this workflow pins. §5.1 requires the URL **shown in full**, so an approval
  record naming the wrong host documents approval for something nobody proposed.

### Changed
- **`AGENTS.md` keeps concurrent sessions apart.** On 2026-10-23 several sessions worked
  `store/events.py` at once, and two defects were each fixed twice in different designs
  (#275 and #276, #277 and #278), with one fix of each pair thrown away. §2 gains a step 8
  that every session runs, however it was started: list the open pull requests and running
  sessions touching the files you plan to change, and stop and ask on any overlap. The two
  append-only logs (`DESIGN.md` §11 and this file) are exempt. A new §6.4 sets one owner per
  item (an agent that queues a task card does not then do that work itself), one open job
  per file set, and a coordinator that, when one is used, is the only dispatcher. §8 forbids
  building on a branch whose pull request is still open, since `main` squash-merges. These
  rules are advisory and say so: GitHub has no cross-session lock.
- **Backup manifest format is `ianua.backup.v2`, and the attestation commits to observable
  *contents*.** `EventStore.attest()` gains `observables_digest` — a sha256 over every sorted
  `(event_id, value)` row, each field length-prefixed — beside the unchanged event digest.
  Review of the promotion gate showed why: replacing observable rows one-for-one left the
  count, the event count, the event digest and `quick_check` all satisfied, exit 0, while
  every indicator pivot joined on values the backup never held. Every attestation field is
  now mandatory in both `--verify` and `--verify-restore` (read from the dataclass, so the
  list cannot lag it), a `SUBSTITUTED` finding names the observables case, and **a v1
  manifest is refused outright** — exit 1, on stderr, stating that this is not a verdict
  on the copy and that the revision which wrote it can still verify it. Route (a) over (b),
  the owner's call; `docs/RESTORE.md` carries the recourse. Two fail-opens were caught by
  the new tests while building it: `_verify_backup` compared only the attestation keys it
  found, and the first fix still indexed a missing field after reporting it, turning the
  finding into a bare `KeyError` on stderr. The covering-index property of `attest()`'s
  statements moved from prose ("both") into a test that imports the SQL the method runs.
  **An independent four-lens review before push then found eleven more**, all confirmed by
  reproduction, among them: a **regression** this change introduced — `--verify` on a backup
  whose store file is missing, or whose manifest `store.path` escapes, raised an
  `UnboundLocalError` traceback where the base branch named the finding (the return dict
  read a variable only one branch bound); `events` was *coerced* with `int()` in
  `--verify-restore`, so a manifest saying `"40"` or `40.9` verified green and `null`
  raised a `TypeError` traceback — every attestation field is now type-checked in one
  place for both verifiers; the digest framed `str()` of each field, which is not injective
  across SQLite storage classes (a `BLOB` `b"x"` and the text `b'x'` digested identically)
  — it now frames storage class, length and raw bytes and never decodes; `--verify-restore`
  never compared `high_water` or `schema_version`; the `ADDED` findings asserted "NOT
  evidence loss", which a count plus whole-set digest cannot establish when rows were also
  substituted; a manifest that is `null`, or lacks `store`/`files`/`chains`, surfaced as a
  traceback; and the "both statements" prose survived in two more docstrings. The
  review's 16 confirmations included the same regression four times, once per lens.
- **Audit of `AGENTS.md`'s measured claims — six were wrong, every one re-measured
  on current code.** The charter is what other agents are told is binding, so a
  claim in it that the code does not hold is a defect. Corrected: (1) §5 said
  indicators come from modelled content "on every path" — measured, all four
  regimes that never decode to a mapping extract the charter's own worked example
  in full, five personal names into the append-only observables table, and the
  security test was named `..._on_every_path` while exercising only the two
  mapping paths; renamed, and
  the residual is now labelled: every verbatim regime carries
  `parse_status="text"` (three of four read `"partial"` before), and
  `tests/security/test_correlation_hardening.py` guards that `correlation/` never reads
  `observables` — measured, it never did, so "false correlation join keys" was an
  unmeasured claim and is retracted. (2) §5 said "credential-shaped paths are refused" —
  `credentials.json`, `secrets.yaml` and `api_token.txt` are accepted; the bullet
  now points at `_DENIED` and says what it does not cover. (3) §5's stage 7
  amendment said six security test files assert `dependencies = []` — it is five,
  now named. (4) §5 said `grep -rni vacuum .` is zero matches — it returns five
  files; scoped to code. (5) §5 said the store "is opened at `auto_vacuum=0`" —
  that is SQLite's default and no pragma sets it, so nothing pins it. (6) §7.1
  gave two wrong exit codes: the unstaged-baseline refusal exits 1 (not 3, and
  the same code as a real finding, so the message is the only signal), the
  line-number rewrite exits 3, and through `xargs` a finding surfaces as 123;
  §7.1 also claimed the filter set is unchanged across a line-number rewrite,
  which is false on the first one. Claims that were re-measured and **hold**:
  the three verbatim-retention residuals, the 58 space-bearing tracked paths and
  the `--` terminator hazard, `scan --baseline`'s silent absorption, the
  read-only collector assertions, `MAX_FIELD_LEN = 2048`, and ~15 GB/month at
  `DEFAULT_BATCH = 1_000` on a `*/5` schedule.
- **`AGENTS.md` §5 gains a stage 7 amendment licensing the active/passive peer
  channel**, and `DESIGN.md` §5 boundary 4 and new boundary 15 record the
  crossing. **Documentation only — no network code ships in this change.** The
  owner approved an inbound listener and egress to a declared peer; §5.1 wants a
  written authorization basis before a boundary is crossed, so the basis lands
  first. The licensed surface is deliberately smaller than either thing it
  permits: a read-only health/state listener on the **active** node, HMAC
  authenticated **in both directions** (the response MAC bound to a fresh request
  nonce, because the response is what informs a promotion decision), bound to an
  address that is refused if it **parses** as unspecified in either family — a
  literal `0.0.0.0` rule caught one spelling of six — and egress only from the
  **passive** node to one host in a committed allow-list that is empty by default.
  What may cross is a **versioned, committed allow-list of named fields**, not a
  category: the distinction is entropy, not aggregation. A request may reach the
  audit chain and nothing else, and must, since a failed authentication is a
  security-relevant action §3 requires recording. It does not fence and cannot
  promote. `dependencies = []` is untouched.
  Review found **six** defects across two rounds and all six were confirmed, none
  refuted — the argument for amending before building rather than after, and the
  second round is the more useful half: a reviewed draft is not a correct one. The
  later two were the `attest()` digest being a **presence oracle at low cardinality**
  (measured: at `count == 1` an `event_id` derived offline from a raw log line
  reproduces the served digest, since the id carries no store-injected entropy and
  `DIGEST_PREFIX` is public — so the digest now crosses as a *comparison* withheld
  below 1000 events, not as a value), and the audit-write bound covering **rejections
  only** (a replayed valid request takes the *accepted* path and needs no key, so one
  captured request could flood the hash chain — both outcomes are bounded now, and
  request freshness is server-enforced rather than echoed into the response).
- **The four scheduled CLIs now exit `4` for retryable SQLite contention**, where
  they returned `1`. `1` had meant both "the evidence store is damaged, page
  someone" and "another writer held the lock for five seconds, retry", which an
  operator must treat oppositely — `docs/RETENTION.md` carried a paragraph
  warning about the conflation rather than the code resolving it. Discrimination
  is on SQLite's *primary* result code (`scripts/_exit_codes.py`), so it covers
  all seven extended `SQLITE_BUSY`/`SQLITE_LOCKED` names without enumerating
  them. Damage still returns `1`, so a wrapper testing `rc != 0` is unaffected
  and one paging on `rc == 1` stops paging for contention. `run_collector`
  reports `4` only when *every* failure in the pass was contention: one damaged
  source alongside a busy one still returns `1`.
- **A `flock` that fails for any reason other than contention is now a refusal,
  not a benign skip.** `single_instance` caught bare `OSError` and yielded
  "another pass holds the lock" for all of it, so on a lab-data root whose
  filesystem cannot `flock` — or whose kernel lock table is exhausted — every
  scheduled pass of all four CLIs printed its skip line and exited `0`, forever,
  with no contention anywhere and no work ever done. The catch is now an
  allow-list of one, `BlockingIOError`; everything else raises
  `LockUnavailableError` and exits `2`.
- **Exit `2` now documents the condition it can be returned for.** A broken lock
  reaches `2`, and all nine statements of the exit-code contract said "bad
  arguments" — the four CLI docstrings, `scripts/_exit_codes.py`,
  `docs/RETENTION.md`, `docs/RESTORE.md` and `docs/PRODUCTION_SOC_PLAN.md`
  twice — so an operator who got a `2` from a failing `flock` was told to check
  their argv. Every operator-facing site now carries the literal message the
  code emits, asserted against it rather than paraphrased. `ENOLCK` was weighed
  for `4` and refused: the one errno covers both a transient kernel shortage and
  a filesystem that cannot lock at all, and retrying the second forever while
  nothing pages is the defect above with a non-zero code.
- **`run_backup.py --verify-restore` now requires `--audit-anchor`, and both verifiers refuse
  hard-link restores.** The manifest's sha256 must match a take record in the preserved source
  `data/events/audit.log` (`docs/RESTORE.md` step 4a). A `cp -al` restore let the gate write
  into the backup's chain; such files are now `LINKED`. Reads are bounded by the manifest's
  sizes, `--verify` takes `verify.lock`, and a skipped verify exits `4` with "Nothing was
  verified." (#266)
- **Streamlit bumped 1.65.0 → 1.66.0, and the `dashboard` floor raised to `streamlit>=1.66.0`.**
  Streamlit 1.66.0 drops its `httptools` and `toml` dependencies, so httptools 0.8.0 and toml
  0.10.2 leave `uv.lock`, `requirements.lock` and the SBOM (now 227 components). The Security
  entry below moves Streamlit on to 1.66.1. (#265)
- **Dev toolchain bumped: ruff 0.17.0 → 0.17.1, hypothesis 6.168.5 → 6.170.0, pre-commit 4.6.2 →
  4.7.0.** The `dev` extra in `pyproject.toml` now pins `ruff==0.17.1`. `uv.lock`, both pip
  locks and the SBOM were regenerated. (#264)
- **`github/codeql-action/upload-sarif` bumped 4.38.3 → 4.39.0 in the Scorecard workflow.** It
  is still pinned by commit SHA in `.github/workflows/scorecard.yml`. (#263)
- **`ContainmentExecutor`'s action method is renamed from `execute` to `perform`.**
  `ContainmentToolkit` now calls `perform`, so a lab executor must define it. The old name was
  the one non-SQL finding once `tests/security/test_sql_provenance.py`, which requires every
  sqlite3 statement to trace to a string literal, began sweeping every shipped package. (#226)
- **`ingest/` retains only what a parser modelled: `raw_excerpt` is rebuilt from declared
  payload paths, never copied.** Each `Signature` declares the paths it reads in `fields`;
  before, a Defender for O365 record's `Body` reached `raw_excerpt`. A record no signature
  claims is projected through the union of every parser's declared paths, with a note naming the
  withheld keys. Separately, an over-long `message` was stored and then made every later `query`
  raise, stopping detection; `NormalizedEvent.bounded()` now applies every read-time bound to
  each parsed event. `AGENTS.md` §5 gains a "What is retained" amendment. (#209)
- **The dashboard binds `127.0.0.1`, pinned in `.streamlit/config.toml` and asserted by a new
  control.** The address was unset, so the bind was whatever the installed Streamlit defaulted
  to, and `dashboard/` authenticates no one. HIGH-severity control `CFG-02` fails on a missing
  config, an unset address, or an address outside its loopback allow-list. Two tests now tie
  `docs/trust.data.json` to `registry()`, so adding a control can no longer leave the trust page
  claiming 16 controls where there are 17. (#207)

### Fixed
Many of these fix components first added in this release, which no tagged version shipped.
They are listed so the record of what changed stays complete.

- **`scripts/report_sli.py` crashed on any stdout whose encoding is ASCII, with no planted data,
  and a healthy platform exited 1.** Every indicator line carries a `—`, so on an ASCII stdout (a
  forwarded locale the host never generated is enough) the report printed its headline and then a
  `UnicodeEncodeError` traceback. Measured on `52d3235`: on a healthy root that was `ok: all 8
  objective(s) met`, then the traceback, at exit 1, the code for a breach. `--help` crashed too.
  `report_sli.py` and `run_backup.py` now call one shared `scripts/_terminal.escape_unencodable`
  first in `main`, which sets stdout and stderr to `backslashreplace`. The line reads `\u2014`,
  nothing raises, and the exit code is the grade again. It is `run_backup.py`'s loop from #255,
  moved rather than copied, and a test refuses another copy under `scripts/`. A UTF-8 stdout
  writes the same bytes as before, and `--json` is unchanged. This closes the residual #280
  recorded. Recorded, not fixed: `--help` on an ASCII stdout still crashes fourteen other CLIs
  under `scripts/`.
- **`scripts/report_sli.py` printed indicator details raw in text mode, and a backup directory's
  name was a live route to the operator's terminal.** `backup-present` names the newest
  directory under `data/backups` and never reads its manifest, so no store bound sees that
  text. Measured on `d1f3369`: a name holding `ESC[2J ESC[H` and a CR cleared the terminal and
  wrote a forged "ok" line above a report that exited 1. A RIGHT-TO-LEFT OVERRIDE displayed the
  name reversed. A name that is not UTF-8 made the report die with a traceback partway through
  on a stdout with strict errors, the `en_US.UTF-8` default. Every line `report_sli.py` prints,
  stdout and stderr, now goes through `scripts/_terminal.printable`, which shows each
  non-printable character as its escape (`\x1b`) rather than dropping it. That function is
  `run_backup.py`'s `_printable`, moved rather than copied, and `run_backup.py` imports it under
  its old name. A test refuses a second `isprintable` escaper under `scripts/`. `--json` is
  unchanged: `json.dumps` already escapes, and it keeps the exact value. This closes the
  "`report_sli.py` escapes nothing in text mode" residual #275 recorded. Recorded, not fixed:
  on an ASCII stdout every text report crashes on the em dash `Indicator.summary` emits, with
  no planted data.
- **A forged `event_id` was echoed whole into the store's hash-mismatch refusal, and from there
  into `store-readable` and the operator's terminal.** `_rebuild` named the stored id in the
  `StoreIntegrityError` it raises when a projection does not hash to it. On that branch the id
  is whatever a row written outside the API holds. Measured: a forged ASCII id of 50,008
  characters made a 50,105-character `query()` refusal, which `sli.measure_store_readable`
  copied into a 50,152-character detail. An id of `"\x1b[2J"` put a raw ESC into that detail,
  and `scripts/report_sli.py` wrote it to the terminal. The id is now named only when it fully
  matches `[0-9a-f]{64}`, the shape every write gives it, and is otherwise described by type and
  length. That is an allow-list rather than #275's bounded `repr`, because no build writes any
  other id, so there is nothing a quote could tell an operator. After: 218 characters, 265 in the detail, and no
  control character in either or on stdout. A hex id is named exactly as before, and the three
  refusals that run after the hash matched still name it. Recorded, not fixed: `attest` digests a
  BLOB `event_id` as `str()` of its bytes, so a BLOB and its TEXT twin attest alike. This is left
  to the owner, because the digest already collides on forged TEXT ids and refusing would stop a
  backup take of a tampered store.
- **`EventStore.attest` let a non-ASCII `event_id` escape as a bare `UnicodeEncodeError`, and
  `Query.limit` took a `bool`.** These are two of three residuals #270 found that #272 did not
  close, each measured on `6696c43`. The third, the schema-version echo, was closed by #275 (the
  entry below). A valid-UTF-8 id written outside the API (`"é" * 64`) passes the connection's
  decoder and failed `attest`'s ASCII encode with an error no `except StoreError` catches. The
  backup take, `--verify` and `--verify-restore` printed the codec's sentence at exit 1 only
  because that class subclasses `ValueError`. It is now a `StoreIntegrityError` that gives the
  id's length, with the codec error suppressed because its `object` is the id. `sli`'s
  `store-intact` reads `1.0` for that row before and after, which is correct: it checks pages and
  never calls `attest`. `Query(limit=True)` read one row and `limit=False` none, since `bool` has
  `__index__`. Both are now `TypeError: limit must be an integer, not bool`.
- **A forged schema version was echoed whole into `SchemaVersionError`, and from there into
  both store objectives and the operator's terminal.** `EventStore.open`'s version-mismatch
  refusal interpolated the stored `meta` value as `str(value)`. Measured: a 50,000-character
  version made a 50,154-character error, which `sli` carried into `store-intact` (50,236
  characters) and `store-readable` (50,225), the detail `AUD-03` tells an operator to record. A
  BLOB was echoed as `str(bytes)`. And a version holding `ESC[2J` reached
  `scripts/report_sli.py`'s stdout raw, clearing the terminal above a forged "ok" line. The
  version is now quoted through `repr` and cut at 32 stored characters (or bytes), with the
  cut and the full length named, the shape `_rebuild_reason` already has. A real version from
  another build is still named whole, now quoted: `version 2` reads `version '2'`. Which stores
  open is unchanged. The bound left `run_backup.py`'s `_printable` on the pass's `error:` line
  pinned by nothing (measured: green with it removed), so a stand-in test now pins that line.
  Six plants, six red. Recorded, not fixed: `report_sli.py` escapes nothing in text mode.
- **`scripts/ask_cyber_kb_ollama.py` and `ask_cyber_kb_chunked_ollama.py` assumed every retrieved
  point carried a dict payload with string text.** `qdrant-client` types the payload as
  `dict | None`, which `mypy` reported five times with the `dashboard` extra installed (CI installs
  only `dev`, so it never saw them). At runtime a `None` or list payload raised `AttributeError`
  before anything was generated, and a non-string `text` was formatted into the model's prompt as
  its `repr`. Both scripts now follow the rule `search_cyber_kb.py` and `ask_cyber_kb.py` already
  did: a payload that is not a dict, or text that is not a string, contributes an empty passage.
- **Two writers could interleave the ordering check, a finite forged mark below the rows was
  obeyed, non-UTF-8 text escaped as a raw driver error quoting its bytes, and `Query.limit`
  was not validated.** These are the three residuals #269 recorded. The connection's default
  transaction handling read the high-water mark outside the transaction its insert then opened.
  Measured with two connections, a second writer committing at 200 between the first writer's
  check and insert at 150 left a row behind a stored row and regressed the mark below the rows.
  `append` and `append_many` now take the write lock (`BEGIN IMMEDIATE`) first, so the second
  writer gets `SQLITE_BUSY`, and `append_many` counts its new rows inside that lock. With no
  write path able to leave one, a stored mark below `MAX(ingested_at)` is now a
  `StoreIntegrityError`. Before, `'1.0'` over rows at 1000 to 1002 let an append at 5.0 through.
  The connection now decodes TEXT itself and raises `StoreIntegrityError` for bytes that are
  not UTF-8. `sqlite3`'s own `OperationalError` escaped `open`, `query`, `attest` and
  `high_water_mark` and quoted the planted bytes. `Query.limit` now goes through the index
  protocol: NaN and `2.5` raised a raw `sqlite3.IntegrityError` and `inf` was taken silently as
  the ceiling, and each is now a `TypeError`. No first-party caller reached any of these. The
  collector is the only writer and holds a single-instance lock, and every limit passed is an `int`.
  `sli` no longer reads that refusal as damage. A tampered schema-version row made `open` raise
  `StoreIntegrityError`, which `_open_store` put on the damage side, so `store-intact` said "the
  store's database is damaged", pointing an operator at a restore. Only `StoreCorruptionError` is
  damage now, so a tampered row reads `unknown` with its reason, as a removed version row already did.
- **A corrupt high-water mark escaped as a bare `ValueError` or was obeyed silently, and a
  NaN query bound read as a quiet period.** `EventStore.high_water_mark` converted the stored
  `meta` mark, and in its no-`meta` fallback `MAX(ingested_at)`, with `float()`. Garbage text
  raised a bare `ValueError` from `high_water_mark`, `next_stamp`, `append` and `attest`, so
  `sli` graded `ingest-freshness`, `detection-lag` and `detection-backlog` "the probe raised".
  A BLOB `b'1.5'` and `±inf` were accepted, and a stored `nan` was worse: every comparison
  against it is false, so an append behind every stored row succeeded and rewrote the mark
  lower, and `scripts/run_retention.py --apply` skipped its clock-fault guard and deleted 5 of
  10 events at exit 0, where the same store with an intact mark is refused at exit 2. Both
  branches now raise `StoreIntegrityError` for anything that is not a finite number, without
  echoing the stored text, and `sli` names the mark rather than saying the store "could not be
  opened". Separately, `Query`'s `since`, `until`, `ingested_from` and both keyset bounds now
  go through `_finite`, as `prune` and `count_before` already did: a NaN bound returned no
  rows with no error and now raises `ValueError` (`TypeError` for text, which `float()` used
  to parse). `run_cycle` refuses a non-finite `lookback` as the CLI already did; called
  directly, `nan` correlated 10 events against the default's 50.
- **A corrupt `ingested_at` read as "could not measure", and NaN or infinite timestamps
  were accepted on both sides.** `ingested_at` is the one column the read path converts that
  the content hash does not cover. A stored row whose value was text or a BLOB escaped `query`
  as a bare `ValueError` (graded `unknown … the probe raised ValueError`), while a numeric
  BLOB (`b'1.5'`) and `±inf` read back silently as stamps. `_rebuild` now converts it
  through `store.events._finite` and raises `StoreIntegrityError` for all of them, so
  `store-readable` reads `breached` with the column named and the stored value never echoed.
  Separately, a hand-built event with a NaN, `+inf` or `-inf` timestamp was stored without
  error and read back unchanged: NaN dropped out of every time window, `+inf` sat in every
  `since=` window and `-inf` in every `until=` one. The reader now refuses them, which covers
  both sides, since `append` runs the reader before it writes. `bounded()` maps them to
  `None`. No parser produces one, so no store written through `ingest/` is affected.
- **`store-readable` graded its own headline failure as unmeasurable.** A stored row that
  hashes to its `event_id` and has a field past its bound (the over-long `message` the
  objective's rationale cites) made `query` raise the reader's `MalformedProjectionError`,
  an `IngestError` rather than a `StoreError`, so the probe read `unknown … the probe
  raised MalformedProjectionError` and `detection-backlog` the same. `_rebuild` now raises
  it as `StoreIntegrityError` chained from the reader's error, so `store-readable` reads
  `breached` with the field named, the query-failure branch #258 kept at `0.0`. Two sibling
  escapes are closed with it (an integer timestamp past float range, and JSON nested past
  the decoder), and the reader's sentence is bounded at 200 characters because two of its
  shapes quote the row.
- **Every chain writer signs with Ed25519 when that is the configured scheme.** All five
  writers (`run_backup`, `run_retention`, `run_pipeline`, `run_collector`,
  `compliance.evidence`) resolved the HMAC-only `signing_key_from_env`, so an Ed25519
  deployment wrote every chain head unsigned and its public-key verifiers reported every
  chain broken, despite `.env.example` telling operators to "sign with the private key".
  The new `agents.policies.audit.signer_from_env` has `verifier_from_env`'s precedence (HMAC,
  then `AUDIT_ED25519_PRIVATE_KEY`). `verifier_from_env` now also verifies with the private
  key on a node that holds only that. A pair that is not one pair is refused on both sides,
  and every unusable key raises the `ValueError` the writers already turn into "refusing to
  run". `--verify-restore` on a node holding only the public key now refuses before writing,
  instead of leaving the restored chain's head unsigned. `compliance.evidence.record_run`
  resolves the signer before appending any evidence line, so a refused run leaves no
  unchained record for `score_history` to count, and the dashboard reports a refused key on
  both the run and the evidence trail instead of a traceback (both found by review). Measured
  red before on `main`: 19 of the 22 new cases in `tests/security/test_audit_writer_signer.py`,
  including every writer end to end and every writer's refusal.
- **A symlink-loop corpus root reads "cannot be resolved" on Python 3.13 as on 3.11 and
  3.12.** On 3.13, `Path.resolve()` no longer raises on a loop and `is_dir()` swallows the
  `ELOOP`, so the root read "not a directory". The root now asks `stat()` for `ELOOP`
  directly.
- **The egress allow-list's mapped-address refusals no longer depend on the CPython patch
  release.** `tests/security/test_egress_allowlist.py` was red on CPython 3.12.3, Ubuntu
  24.04's system Python and inside `requires-python`, so a contributor running §7 locally
  got a failing suite while CI, on the latest 3.12 patch, stayed green. Measured:
  `is_unspecified` for `::ffff:0.0.0.0`, `is_link_local` for `::ffff:169.254.169.254` and
  `is_multicast` for `::ffff:224.0.0.1` are True on 3.11.17 and 3.13.16 and **False on
  3.12.3**, which does not delegate them to the mapped IPv4 address. Every mapped address
  was still refused, by the IPv4-mapped rule, so the product was safe. On that interpreter,
  though, the metadata address written as `::ffff:169.254.169.254` rested on that one rule,
  and `parse_address`'s docstring claimed it was caught as link-local "(measured)".
  `parse_address` now reads the address a mapped form denotes before its unspecified,
  multicast, broadcast and link-local refusals, so each has one reason everywhere and the
  IPv4-mapped rule is a second layer on every interpreter. The set of refused addresses is
  unchanged. The test's premise now reads the denoted address too, the shape test pins its
  reasons instead of ignoring them, and a new case reproduces 3.12.3's non-delegating
  properties with stand-ins (checked against the real 3.12.3: no disagreements over 15
  addresses). That case is red against the old code on 3.11, 3.12.3 and 3.13, so CI now
  guards an interpreter it does not run. AGENTS.md §5 (both the stage 7 listener bullet
  and the lab-host bullet) and DESIGN.md boundary 15 carried the same measured claim and
  now say where it holds. The listener's future bind refusal is told it owes the same
  unwrap.
- **The SLI reporter called a store that would not open "damaged".** `store-intact`
  graded every `StoreError` as `0.0` with "the store's database is damaged", so since #257
  a FIFO `-journal` read "the store's database is damaged: … has a -journal beside it that
  is not a regular file (a FIFO)". The detail named the real cause, but the label pointed
  at the restore branch, and a restore replaces the SOC's memory with an older copy of a
  database nothing had touched. The same mislabel already applied to a symlinked `data/`
  (`StorePathError`), a schema version this build does not speak, and a store whose
  version row was removed (`SchemaVersionError`). Measured on `9ff3604`, all four read
  `breached` on `store-intact` and `store-readable` alike. They now read `unknown` with
  "the store could not be opened" and the store's own reason. Damage SQLite reports
  itself (`StoreIntegrityError`, so `StoreCorruptionError` included) is still `0.0`
  whether `open`, a query or the quick check meets it. `UNKNOWN` is not a pass, so
  `scripts/report_sli.py` still exits `1` in every case. The damage verdict is now an
  allow-list of one class: a `StoreError` added later reads `unknown` until someone
  decides it means damage. `tests/security/test_sli_hardening.py` pins the four refusals
  in-process, the FIFO through the CLI in a subprocess, and damage at each of its three
  stages. Six planted regressions each turn at least one of those tests red.
- **`--verify-restore` failed every correct restore whenever `AUDIT_HMAC_KEY` was set.**
  `_is_append_only` granted growth to every file whose name starts with a declared stream's,
  so the head signature `audit.log.sig` was prefix-compared. But every signed `record()`
  replaces that file whole, and the gate's own decision re-signs `data/events/audit.log`
  before the comparison runs: `REWRITTEN: data/events/audit.log.sig`, exit 1, on a restore
  nothing had touched. No test set a key, so the suite stayed green. Now only the five
  declared streams may grow. Every head signature must be present. Only the one this
  command re-signs, `data/events/audit.log.sig`, may skip the byte comparison, and only
  where its chain verified it under the key (or the chain is already a finding). Every other
  signature is compared exactly, key or not: nothing writes those chains in this window, and
  the key check reads three fields of a signature and no others. The chain verdict is the
  last read the pass makes, after every stream, report and signature comparison, so an
  unquiesced writer's append cannot slip in behind it. Three review rounds found gaps in
  earlier versions of this fix: a signature beside a fully pruned chain that nothing
  checked, chain verdicts taken before later reads, and edits to signature fields the key
  check never reads. The same rule had granted growth to rotated
  archives and checkpoints, which never grow: blank lines appended to an archive, or
  whitespace to a checkpoint, verified green. Both are exact now. On the backup side the rule
  copied `audit.log.lock` into every backup, despite `docs/RESTORE.md` saying `*.lock` never
  lands there; it no longer does, and older backups that carry one still verify. All of it
  measured red before and green after in `tests/security/test_promotion_verify.py`.
- **The required pre-commit gate had been dead on `main` since #232, and the
  Scorecard action it carried could never have run.** #232 appended three lines
  to `.pre-commit-config.yaml`: a `- name:` / `uses:` pair, which is GitHub
  Actions syntax rather than a pre-commit repository mapping (those need `repo`,
  `rev` and `hooks`), misindented so the file was not valid YAML. Measured on the
  merge commit `c043b1c`: `yaml.safe_load` raised a `ParserError` at line 134,
  `pre-commit validate-config` exited 1, and `pre-commit run --all-files` died
  with `InvalidConfigError` **before any hook ran** — so ruff, ruff-format, mypy,
  bandit, `detect-secrets`, `detect-private-key`, `check-yaml` and the drift gates
  were all silently skipped for every developer. A grep for `detect-secrets`
  passed throughout the outage, which is why "declared" is not the property that
  matters: the file has to **load**.
  `.github/workflows/ci.yml` now runs `pre-commit validate-config`, which is the
  gate that would have caught it. Two test layers back it up and are not
  redundant: `validate-config` proves the file loads, while
  `tests/unit/test_scorecard_workflow.py` proves nothing Actions-shaped has been
  pasted back and `tests/security/test_scorecard_boundary.py` asserts the two
  secret scanners are reachable *through a file that parses*.
- **`--verify-restore` exited `0` on three restores it should have refused, and in
  every case the manifest already carried the datum the check never read.** Found
  by review on the merged gate; all three measured through the shipped CLI before
  anything was changed, and fixed together because they share that shape and two of
  them turn on one classifier. An earlier version of this entry said they "live in
  one ~60-line loop", and that was never measured. Measured: `_verify_restore` is
  258 lines; only the report comparison is inside the manifest loop, the reverse
  walk is a separate loop after it, and the observables check is a separate block
  before it. The observables fix could have shipped alone.
  **Observables were never compared.** The completeness digest is a sha256 over
  the `event_id` set only, so observables are not in the preimage. Measured: 20
  observable rows destroyed of 20, events untouched — `quick_check` ok, event
  count equal, digest equal, **exit 0**. An indicator pivot (`query(observable=…)`) returns
  nothing on such a store — the pivot and the attestation are what lose; `correlation/`
  never reads `observables`, and an earlier version of this entry said it did. The number was
  sitting in `manifest["store"]["attestation"]` the whole time. `LOSS` now covers
  it, with `ADDED` for the legitimate re-collection direction.
  **Report entries were compared by prefix.** `_digest_prefix` hashes only the
  first *n* bytes, which is right for an append-only stream and wrong for a
  report. Measured: a 40-byte declared report, 94 bytes live with the prefix
  intact — **exit 0**; and the same with 512 NUL bytes appended — also **exit 0**.
  Reports are now compared by exact size *and* digest (`ALTERED`), while the hash
  chains and the evidence stream keep prefix semantics. The allow-list is on the
  **growing** side, so a tree added to `COPIED_TREES` later gets the strict
  comparison without anyone remembering to ask: granting growth to something that
  cannot grow hides a rewrite, while demanding equality of something that does
  grow produces a loud finding an operator can read.
  **The manifest was walked in one direction only.** `docs/RESTORE.md` step 4 is a
  bare `cp -a`, which **merges** into a nonempty destination rather than replacing
  it, so a file written after the backup survives the restore — and the loop
  iterated `manifest["files"]`, so it could not see one. Measured: a backup at 20
  events with one declared report, a live root grown to 35 events and a second
  report describing them, store deleted and `cp -a` applied — **exit 0**, with
  that report still claiming "Correlated 35 events" over a store holding 20, in
  the tree `dashboard/app.py` reads. The live inventory of the copied trees is now
  compared against the manifest (`UNDECLARED`), scoped to `COPIED_TREES` because
  the rotation siblings beside the chains legitimately appear after a backup and a
  blanket reverse walk would false-alarm.
  Eight `tests/security` cases, each paired with a control direction, and the
  append-only/strict classifier is pinned from **both** sides: forcing everything
  strict reds `test_a_correct_restore_verifies` — this command's own gate decision
  appends to `data/events/audit.log` before the check reads it — and forcing
  everything prefix reds the two report cases.
  **Review then found two fail-opens in the fix itself**, which is the part worth
  recording. *A symlinked `data/reports` was skipped rather than reported*: the
  reverse walk's `continue` was lifted from the backup side, where refusing to
  descend a link is correct, and on the verify side the same line is how the link
  survives — measured, a backup declaring no reports restored over a root whose
  `data/reports` points outside it exited `0`, with a planted file readable as this
  node's report. Two guards exist for exactly that and each declined it for a
  different reason. *And the new observables comparison was guarded by
  `isinstance(...) and isinstance(...)`*, so a manifest that omitted the field, or
  carried `"20"`, silently skipped the check — measured, deleting the field **and**
  every live observable row gave exit `0`. The manifest is untrusted input here, so
  both now fail closed.
- **`EventStore.open` refuses a FIFO, linked or non-regular database or sidecar before SQLite
  opens it.** A FIFO `-journal` hung every CLI that opens the live store, and a hard-linked
  `-shm`, `-wal` or database had its other name written, some at exit 0. The database and its
  `-journal`, `-wal` and `-shm` must each be absent or a regular file with one link; anything
  else raises `StoreFileError` or `StoreSidecarError`, and every CLI exits 1. (#257, #259)
- **`run_backup.py` checks every SQLite sidecar, fails the take closed, and escapes its
  output.** A backup's `-shm` hard-linked to the live store let a plain `--verify` destroy it at
  exit 0, and a FIFO `-journal` hung the take while it held the lock; each sidecar must now be a
  regular file with one link. A `files[]` path carrying terminal escapes could forge report
  lines; every printed line is escaped. A symlinked `data/events` is refused before the gate
  record. (#255)
- **The embedded Qdrant store is anchored at the source tree, and the KB scripts read the corpus
  safely.** `QDRANT_PATH=` put the store in the working directory; unset or empty now means
  `data/qdrant` under the tree, and a relative value outside `data/` raises `QdrantPathError`.
  Corpus files are read through one bounded `O_NOFOLLOW` descriptor. `ingest_cyber_kb.py` ids
  were directory positions and are now `uuid5` of the source path; old integer points are not
  removed. (#254)
- **The rename gate stays inside the repository, and the ATT&CK and YAML gates refuse hostile
  input.** `rename_to_ianua.py --apply` rewrote files outside the checkout through links, and
  reports under `data/`; it now uses `O_NOFOLLOW` descriptors, skips `data/` and fails `--check`
  on a file that is not NUL-free UTF-8. `update_attack.py --build` validates the staged index
  before any write. `build_attack_navigator.py` and `build_behavior_index.py` exit 2 on YAML
  aliases, rules over 256 KiB and nesting past 32. (#253)
- **The backup verifiers check a manifest's shape and do not open a store that opening would
  write.** `--verify` created a store inside a backup whose `store.path` named another file, and
  grew a 0-byte backup store to 61440 bytes; both are now findings. `run_pipeline.py --lookback
  nan` ran as `--lookback 0`, and `run_retention.py --keep-days 1e305` failed at exit 1 after
  the gate record; both now exit 2 first. `prepare_release.py` refuses a `--date` not spelled
  `YYYY-MM-DD`. (#252)
- **The pipeline refuses a non-finite cursor, and compliance and SLI checks no longer follow
  links or misreport.** A `NaN` cursor made every cycle read zero events while
  `detection-backlog` graded `met`; it is now a `CursorError`. The corpus check ran an `attack/`
  package planted under the root it graded, a symlink at `evidence.jsonl` carried evidence
  outside the root, and `backup-present` counted a symlinked backup; each is refused. A run with
  no automated controls is chained as `attention`. (#251)
- **Ingest claims BOM-prefixed records and recognizes auditd only on its own fields.** A JSON
  record behind a UTF-8 BOM was carried verbatim, mail `Body` included; the mark and whitespace
  are now stripped at both edges before detection. A known auditd `type` plus any `msg` was
  claimed as auditd; `msg` now corroborates only when it starts with the
  `audit(<epoch>.<ms>:<serial>)` stamp. On bytes, `MAX_RAW_BYTES` applies before decoding, and
  ISO timestamps share the numeric plausibility window. (#250)
- **The incident report escapes the AI narrative, and mapping, response and risk inputs are
  validated.** Model output was written verbatim, so a heading, an image beacon or a NUL byte
  reached the report and the PDF; it is now escaped like log fields. The mapping ruleset raises
  `MappingStoreError` for every anomaly, refuses duplicate keys and applies `MAX_STORE_BYTES`
  across all files. Technique ids must be ASCII `T1234` or `T1234.001`, and risk scores finite
  and within 0..100. (#249)
- **The Pages deploy runs only for a CI push to `main` in this repository, and write scopes sit
  on the job.** A fork's pull request from a branch named `main` could enqueue a deploy under
  the approval gate and cancel one already waiting. The gate now also checks the event, head
  branch and head repository, the `pages` concurrency group is on the `deploy` job, and
  `pages.yml` and `dependabot-automerge.yml` grant writes per job. A manual CI dispatch on
  `main` no longer refreshes Pages; dispatch `pages.yml`. (#248)
- **Correlation no longer joins hosts on placeholder or mis-shaped values, and `attest()` reads
  one snapshot.** `10.0.0.5` and `10.0.0.7` in a hostname field both became host `10`, and
  loopback spellings such as `0:0:0:0:0:0:0:1` were join keys; addresses are judged on the
  parsed value and only a wholly DNS-shaped name is short-formed. `attest()` raised "attestation
  is inconsistent" when a commit landed mid-read; it now reads in one transaction. `prune`
  refuses a non-finite threshold, and the schema and its version row commit together. (#247)
- **Containment refuses links, and the LLM adapter checks egress per request and fails closed.**
  A quarantine path swapped for a symlink or hard link changed the mode of a file outside the
  root; each act now uses one `O_NOFOLLOW` descriptor with one link. `agents/tools/llm.py`
  checked `host` only at construction and followed redirects and `http_proxy`; it now checks
  each request, refuses every 3xx, uses no proxy and raises `ValidationError` on a malformed
  reply. A Sigma list under a bare field is any-of. (#246)
- **The policy bundle loader is strict, and a planted file can no longer hang or half-write the
  audit chain.** A repeated `allow` key enforced a grant the first key showed empty; duplicate
  and unknown keys, a `version` other than the integer 1 and a non-`deny` `boundary_crossing`
  are now refused. A FIFO at `audit.log.lock`, `audit.log` or `audit.log.sig` hung `record()` or
  `verify_report()`; every chain open now refuses a symlink or non-regular file. The head
  signature is staged before the append, so a failing signer leaves no unsigned entry. (#245)
- **The intel single-source cap counts only feeds asserting `malicious`, and the intel and
  ATT&CK loaders fail closed.** Feed A `benign` plus feed B `malicious` returned `malicious`
  uncapped, as did an IP declared `md5`; only `EXEMPT_SHAPES` values escape the cap now, and an
  upstream must be a lowercase hostname, not an IPv4 literal. Suppression missed
  `::ffff:10.0.0.1`, and `never_flag.json` loaded `2886729729` as `172.16.0.1/32`; entries must
  be canonical strings. Malformed JSON raises each loader's own error. (#244)
- **The dashboard escapes log-derived text before Markdown and fails closed on a hostile audit
  chain.** A `src_ip` holding a Markdown image reached `st.markdown` verbatim, so the analyst's
  browser would fetch an attacker-chosen URL; such values now pass through
  `dashboard/markdown_safety.py` and reports render with `st.code`. `load_chain_view` raised
  tracebacks or hung on non-UTF-8, nested, FIFO or oversized chains; the approvals tab now shows
  each as an error. `ensure_ollama_running()` tries `ollama serve` once per process. (#243)
- **A lock path that is not a regular file makes the four scheduled CLIs exit 2 instead of
  hanging or following it.** A FIFO with no reader hung every pass, one with a reader let the
  pass run at exit 0, and a symlink had its target chmodded or, if dangling, created outside the
  lab-data root. The lock is one `os.open` with `O_NOFOLLOW` and `O_NONBLOCK`, checked with
  `S_ISREG` on the descriptor. A symlinked lock file, such as one moved onto tmpfs, is now
  refused. (#228)
- **The four scheduled CLIs now set their lock directory to `0o700` on every run.** `mkdir` does
  not change an existing directory's mode, and only `run_backup` followed it with a `chmod`, so
  `data/collect/` and `data/pipeline/` kept whatever mode they were created with. The four
  copies of the lock code are now one module, `scripts/_locking.py`. (#225)
- **`AUD-03` no longer tells its attester to sign on `scripts/report_sli.py`'s exit code.** The
  report read exit 0 and `met=8` before and after a prune removed 24 of 24 events, and the hint
  becomes the evidence `detail` verbatim. It now asks for `store-readable`'s row counts and says
  not to attest while they are zero or below the last attestation until a retention pass and a
  backup manifest account for the drop. The description states that nothing enforces this.
  (#223)
- **Retention no longer charges already-read events to a stalled cycle, and `--before` bounds an
  `--apply` to its dry run.** The unprocessed figure was derived by subtraction and counted the
  read part of the cursor's own commit; it is now counted through the keyset with
  `EventStore.count_before(after=...)`. The threshold was re-derived from the clock, so a dry run
  reported `events_matching` 7 and the apply removed 12. `--before <epoch>` caps the window at
  `min(--before, now - --keep-days)`. (#222)
- **The §7.1 secret gate can run, and CI now runs it.** `$(git ls-files)` word-split the 58
  tracked paths with spaces and exited 2 having scanned nothing. The command is now
  NUL-delimited and ends with `--`, since a tracked file whose name begins with a dash was read
  as a flag and exited 0 unscanned. CI ran only gitleaks, which stayed green while this gate was
  red on two findings unbaselined since #217; `.github/workflows/ci.yml` now runs both. (#221)
- **A raised `--batch` or a retention pass no longer silently shrinks an incident.** Context
  shared one row ceiling with the batch, so `--batch 10000` reported zero incidents where
  `--batch 1000` found a score-52 one; half the ceiling is now reserved for context when
  `--lookback` is non-zero. Retention could delete rows the lookback re-reads (score 52 fell to
  30); `scripts/run_retention.py` now keeps `--lookback-margin` seconds behind the cursor,
  defaulting to `pipeline.DEFAULT_LOOKBACK`. (#219)
- **Concurrent writers and log rotation can no longer fork an audit chain.**
  `AuditLogger.record` read the last entry and appended with no lock, so two writers produced
  seqs `[0, 0]`, and `run_retention.py` and `run_backup.py` write `data/events/audit.log` under
  different pass locks. `record` and `apply_retention` now hold a blocking `LOCK_EX` on a
  `<chain>.lock` sidecar. The head signature is replaced atomically and `verify_report` takes a
  shared lock, so an intact chain no longer reads broken mid-write. (#218)
- **Indicators come only from what an event retains, so withheld prose no longer becomes
  observables.** An unclaimed record's raw text was scanned while its un-modelled values were
  withheld, storing fragments such as `Mr.Jones` and `44.Smith` as observables. The first fix
  scanned one serialized string, so a long modelled field pushed a later URL past
  `MAX_FIELD_LEN` (#215); the second scanned leaves `MAX_RAW_EXCERPT` had cut (#216). An
  indicator only in an un-modelled field is no longer extracted. (#214, #215, #216)
- **Scheduled CLIs refuse a relative or filesystem-root `--root`, and audit maintenance fails
  closed.** An unset `$IANUA_ROOT` passed every check and built a shadow `data/` tree in the
  working directory; `store.paths.validated_root` now requires an existing absolute directory
  other than `/`. `scripts/audit_maintenance.py` exits 2 when `--log` holds no log, and no
  longer renames a directory named by `--log`. Every chain reader resolves `verifier_from_env`,
  so an Ed25519 head signature is checked rather than reported `unsigned`. (#213)
- **The private security-advisory link in the issue chooser names the real repository.**
  `.github/ISSUE_TEMPLATE/config.yml` shipped the `OWNER/REPO` placeholder, which 404s, and with
  `blank_issues_enabled: false` it was the only route offered to a reporter. It now names
  `IRsoctierDT/IANUA`. Issues are disabled, so the defect was latent.
  `tests/unit/test_github_config_placeholders.py` sweeps `.github/` for placeholders and foreign
  slugs. (#211)
- **An unrecognized line of 2049-4096 characters no longer breaks every later cycle, the event
  database is owner-only, and incident reports leave the git tree.** `message` was bounded at
  `MAX_RAW_EXCERPT` but validated at `MAX_FIELD_LEN`, so every `query` after the write raised
  `MalformedProjectionError`. `EventStore.open` narrows the database and its sidecars to 0o600
  in a 0o700 directory, an existing store included. Reports default to `data/reports/`, and a
  destination inside the repository but outside `data/` is refused. (#206)
- **The collector no longer strands events behind the cursor, skips the rest of an over-long
  line, or swallows auditd's nested fields.** One `ingested_at` per pass let a cycle save a
  cursor inside the tie group, leaving 30 of 60 events permanently unread; each source is now
  stamped before its own commit. An over-long line advanced past bytes it never emitted (4505 of
  5410 bytes lost) and now advances by what it emitted. auditd's nested `msg=` payload pairs
  are merged, first occurrence winning, and `?` and `(none)` join `NEVER_JOIN`. (#205)
- **The detection cycle's lookback no longer hides incidents, and a failed report no longer
  loses them.** A newest-first limit applied before filtering left a backlogged store with 200
  events read and 0 correlated; the read is now bounded by `Query.ingested_before`. A wider
  window could push a join key past `max_entity_fanout`, so incidents only the narrow window
  finds are now kept. `scripts/run_pipeline.py` reports before saving the cursor, renames the
  JSON key `cursor_advanced` to `cursor_advancing`, and gains `--include-seen`. (#203)
- **Two false compliance attestations are withdrawn, and MAN-01 now claims only what `main`'s
  rulesets enforce.** MAN-01 and MAN-02 read ATTESTED on claims the GitHub API disproved. Both
  now read MANUAL, and trust-page coverage falls from 16/16 to 14/16 on all three frameworks.
  MAN-01 no longer claims pull-request-only merges or review. (#195, #196, #197)
- **`release.yml` can republish a tag cut before `scripts/release_notes.py` existed.**
  `release-on-merge.yml` dispatches with `--ref main`, so main's recipe runs against the tag's
  tree, and the notes step #193 added would have failed on the missing script for every tag that
  predates it, v2.2.0 included. The step now warns and falls back to `--generate-notes` when the
  script is absent. New releases still get the curated notes through `--notes-file`. (#194)

### Security
- **Pillow 12.3.0 → 13.0.0, unblocked by Streamlit 1.66.0 → 1.66.1; certifi and virtualenv
  bumped with it.** `pip-audit` began failing every pipeline, `main` included, on 27 newly
  published advisories in the pinned closure: 24 in Pillow 12.3.0, all fixed in 13.0.0, two in
  virtualenv 21.14.5 and one in certifi 2026.6.17. Pillow could not move on its own, because
  Streamlit 1.66.0 declares `pillow<13,>=9.2.0`. Streamlit 1.66.1 declares `pillow<14,>=9.2.0`,
  and reportlab 5.0.1 (the other dependent) declares `pillow>=9.0.0`, both read from the published
  metadata. The `dashboard` floor is raised to `streamlit>=1.66.1` so a resolution cannot fall back.
  `uv lock --upgrade-package` changed exactly those four packages and the project floor, with none
  added or removed. Both pip locks were regenerated by `scripts/refresh_locks.py` and the SBOM by
  the `security/sbom/README.md` procedure, still 227 components. `pip-audit` on the new lock:
  "No known vulnerabilities found". This supersedes #267, which bumped certifi and virtualenv
  but could not move Pillow.

### Known issues
- **`--help` raises `UnicodeEncodeError` on an ASCII-only stdout in fourteen CLIs under
  `scripts/`.** A stdout that cannot encode a character in the help text is enough, such as
  a forwarded locale the host never generated. Measured on `scripts/run_retention.py`:
  `PYTHONIOENCODING=ascii` exits 1 with the traceback, and `PYTHONIOENCODING=utf-8` exits 0.
  So a UTF-8 locale, or that variable, works around it. `scripts/report_sli.py` and
  `scripts/run_backup.py` already escape what such a stdout cannot encode (#281).

## v2.2.0 — Release Automation & Control Integrity — 2026-10-13

### Added
- Session-only review of redacted IANUA-Broker JSON scan reports with finding
  filters and remediation guidance in the Streamlit dashboard.
- Baseline/current comparison with new, changed, unchanged, resolved, and
  incomplete-inspection-aware not-observed findings.
- Release automation: `scripts/prepare_release.py` bumps every version
  surface atomically (fail-closed, full rollback), and
  `release-on-merge.yml` tags the CI-verified commit and dispatches the
  signed release once a human approves the `release` environment
  (runbook: `docs/RELEASING.md`).
- **30-day attestation warning window** — `scripts/build_trust_page.py` warns
  on a separate advisory channel 30 days before a manual-control attestation
  lapses, emitted as a `::warning::` workflow command so it lands on the
  Checks tab. Lapsed attestations are reported only by the failing gate, never
  through both channels.

### Documentation
- Research record: 2026 security scanner landscape and ranked IANUA feature
  backlog (`research/2026-10-09-security-scanner-landscape.md`).
- **Path and assertion reconciliation audit**
  (`docs/PATH_RECONCILIATION_AUDIT.md`) — a repo-wide audit of drift between
  what this repository asserts about itself and what is true, with a per-stage
  remediation tracker. Its structural finding: derived artifacts are gated by
  eleven `--check` scripts, the repository's self-description by none.

### Removed
- **`.github/SECURITY.md`** — GitHub resolves a security policy from `.github/`
  before the repository root, so the 18-line stub was the policy the Security
  tab served while the detailed 83-line root `SECURITY.md` sat shadowed. The
  stub described itself as "a pointer so the two can never diverge" and was in
  fact a partial copy of five substantive items, which is how it diverged.
  Deleting it makes the root policy the served one. Nothing unique was lost;
  no generator emits the path; nothing linked into it; and both gates that
  read `SECURITY.md` resolve the repository root, so neither is affected.

### Fixed
- Add an explicit release-assets dispatch that builds and validates before
  creating a release, supports repair of existing releases without moving tags,
  and retains assets with SHA-256 checksums for publication recovery.
- **Attestation-expiry gate was inert** — it compared expiry against the frozen
  committed snapshot date, which only moves on `--snapshot`, so the comparison
  stayed false past the expiry date and no lapse could turn CI red. It now
  evaluates `Attestation.valid_on` against the current UTC date, sharing one
  definition of "current" with the compliance engine, and checks the window's
  lower bound so a post-dated attestation no longer passes.
- **Dependabot tool bumps routed to the wrong group** — `dependency-type:
  "development"` matched nothing, because everything in
  `[project.optional-dependencies]` classifies as production, so every ruff,
  mypy and pytest bump fell through to the human-review-only `runtime` group.
  Tools are now matched by name, with the groups disjoint by construction so
  no reordering can reroute a bump.

### Security
- **Dependabot auto-merge gated on the pushing actor, not just the author** —
  the job checked `pull_request.user.login`, which stays `dependabot[bot]`
  whoever pushes, so a human push to a `dependabot/*` branch was never
  excluded as the control's own comment claimed, and `fetch-metadata`'s commit
  verification did not supply the exclusion either. Auto-merge now requires the
  author, `github.actor` and `github.triggering_actor` to all be Dependabot,
  failing closed so a human-touched bump is merged by a human.

## v2.1.0 — Detection Intelligence & XDR Foundation — 2026-10-05

### Added
- **Multi-source telemetry ingest (`ingest/`)** — the XDR front door. Ten
  parsers across five domains (Sysmon and auditd; Zeek and Suricata EVE; AWS
  CloudTrail and Azure Activity; Entra ID sign-ins and Okta System Log;
  Defender for Office 365 and Google Workspace) normalize into one
  `NormalizedEvent`, so classification, ATT&CK mapping, behavioral matching,
  and response planning stop caring which product emitted a record. A
  normalized event bridges to the existing detection content through
  `to_match_view()`, which the Sigma evaluator consumes directly.

  Three rules govern the layer, each backed by tests rather than by prose:
  **recognition is never a guess** — a record is parsed only when one parser
  signature claims it on distinctive keys, and a record two signatures claim
  is attributed to neither, because mis-attributing a cloud record to an
  endpoint parser produces a confident wrong analysis; **nothing is dropped**
  — oversized, over-nested, undecodable, and type-confused records still
  yield an event with `parse_status` demoted and a note saying what happened;
  and **nothing is ambient** — no clock (a substituted "now" would fabricate
  the ordering correlation depends on), no filesystem, network, subprocess,
  or dynamic exec, asserted over the package's AST. Email is held tighter
  still: `EmailContext` has no body field, and a security test proves no
  parser in any domain reads one.
- **OCSF classification for structured events** — `normalize_source_event()`
  keys off `(source_type, activity)` rather than re-deriving a class from
  prose, and reports `mapped: False` when it fell back to a domain default or
  Base Event, so "classified" is never confused with "defaulted".
- **Detection-intelligence layer** (tracked plan:
  `docs/DETECTION_INTELLIGENCE_PLAN.md`) across three merged slices:
  `attack/` — a version-pinned, hash-verified local MITRE ATT&CK corpus
  (Enterprise 19.2) with tombstoned revocations and merge-blocking reference
  gates; `agents/mapping/` — the MITRE mapper's if/elif ladder replaced by a
  committed, digest-gated ruleset with multi-technique attribution;
  `intel/` — a first-party behavioral threat-intelligence library
  (ATT&CK-anchored, review-aged) plus a synthetic atomic seed with per-type
  confidence decay, never-flag policy suppression, and two-source
  corroboration. The Sigma condition evaluator gained real operator
  precedence and parentheses (previously `a and not (f1 or f2)` evaluated
  wrong), and incident-report rendering now sanitizes untrusted text in all
  three Markdown positions it reaches. Runtime dependencies remain empty.
- **Apache-2.0 licensing** — the repository carried no license, which legally
  means *all rights reserved*: the public could read the code but not use,
  fork, or build on it. Now licensed under Apache-2.0 (canonical text fetched
  from apache.org, not reproduced from memory), chosen over MIT for two
  properties this project needs: an express **patent grant**, and §6's
  explicit **non-grant of trademark rights**, which keeps the IANUA marks
  reserved while the code itself is open.
  - `LICENSE` — full Apache-2.0 text, copyright attributed to the author
    declared in `pyproject.toml`.
  - `NOTICE` — attributions and reservations: IANUA trademark reservation
    (fork freely, brand it your own), descriptive third-party marks
    (MITRE ATT&CK®, NIST, OWASP®, CIS®, CompTIA®, Sigma, SOC 2®, ISO 27001),
    and content provenance stating that knowledge-base entries are original
    summaries citing primary sources, detection rules are original work,
    compliance mappings are this project's interpretation rather than
    certification or advice, and sample logs are synthetic.
  - Machine-readable metadata: `pyproject.toml` uses the PEP 639 SPDX
    expression with `license-files`, `package.json` declares the SPDX id, and
    the CycloneDX SBOM's **root component** now carries its own license so
    consumers see the terms of the artifact, not only of its dependencies.
    Verified in a real build: the wheel emits `License-Expression: Apache-2.0`
    and bundles both LICENSE and NOTICE.
  - Human-facing: README license section and governance-table rows, a
    `CONTRIBUTING.md` inbound=outbound clause (Apache-2.0 §5, no CLA), and a
    copyright line plus License link in the Pages footer.
  - `docs/IP_AND_LICENSING.md` records the reasoning so it does not have to be
    reconstructed later: why Apache-2.0 over MIT (§3 patent grant, §6
    trademark non-grant), why the copyright holder is the individual author
    rather than the GitHub handle (pseudonymous-term and enforcement friction;
    assignable to an entity later), why no LLC yet and what would trigger one,
    the trademark sequencing constraint (an application must name the owner,
    so the entity decision comes first), and the patent position — public
    disclosure already forecloses absolute-novelty jurisdictions, and
    Apache-2.0 §3 licenses your patents to users anyway, so anything genuinely
    patent-worthy must be held back and filed before publication. Facts are
    separated from judgment, primary sources are cited, and the items needing
    an attorney or CPA are named explicitly.

### Added
- **Adversary-in-the-Middle (T1557) detection coverage, end to end** — the
  agent vocabulary had no concept of on-path attacks; ARP poisoning logs fell
  through to `unknown security event` (severity `unknown`) or were absorbed by
  the generic `ids alert` rule. Now wired through every layer:
  - **Detection content**: `arp_cache_poisoning.yml` (base rule — IP-to-MAC
    rebinding anomalies, with a DHCP-lease filter so legitimate churn is not
    alerted) and `arp_cache_poisoning_burst.yml` (correlation — ≥3 anomalies
    from one MAC in 5 minutes, `critical`).
  - **SOC Analyst Agent**: new `arp spoofing` event type classified *before*
    the generic IDS rule (an IDS alert about ARP spoofing is still AiTM
    activity, and the specific class carries the T1557 mapping), triaged
    `high` on a single indicator — AiTM setup precedes credential and session
    interception.
  - **Sequence correlation**: `arp_spoof_burst` pattern (≥3 anomalies per
    validated source, `critical`), keyed per source so unrelated hosts never
    merge into a false burst, with containment-first recommended actions
    (isolate the MAC at the switch port, capture before disturbing, rotate
    credentials used on the segment, enable dynamic ARP inspection).
  - **MITRE Mapper**: T1557 mapping whose recommended investigation prompts
    the analyst to rule out DHCP churn and VIP failover before treating the
    rebinding as hostile.
  - **Detection Matcher**: `arp_spoof_burst` → T1557/T1557.002, so a burst
    finding cross-references the correlation rule (and only it — the base rule
    shares the tags but is single-event).
  - Bundled `sample-logs/arp_spoofing.log` scenario in the dashboard batch tab
    for one-click testing. Ten new tests across the four layers.

### Added
- **Business Proposal + Legal/Compliance agents advanced to active status** —
  the two "business cell" agents the landing page still carried as idle/review
  are now active-grade:
  - *Legal/Compliance*: **multi-topic classification** fixes a real
    correctness gap — first-match-wins silently dropped checklists when an
    inquiry crossed areas (the agent's own canonical example, a subpoena for
    customer data, lost the litigation checklist with its preservation and
    response-deadline items; it now gets both regimes' checklists, merged and
    deduplicated). Adds fail-soft **local knowledge-base grounding**
    (framework notes as supporting context, never authority) and a
    **counsel-ready intake memo** renderer that separates facts, assumptions,
    and unknowns per the governance rules, leads with the mandatory
    disclaimer, and collapses untrusted text so it cannot inject Markdown
    structure. `topic_area` stays as the primary area for backward
    compatibility.
  - *Business Proposal*: **charter-structured SOW renderer** following the
    AGENTS.md §9 deliverable format (Executive Summary · Objectives ·
    Architecture/Process · Implementation Steps · Risks · Cost Considerations
    · Future Enhancements) with cost cells as explicit human-estimation
    placeholders — the agent still never invents pricing, timelines, or
    commitments — and the same injection-resistant line collapsing.
  - Landing-page agent grid flips both to `active` with updated capability
    descriptions. Ten new tests pin the multi-topic merge, memo/SOW structure
    and ordering, placeholder-only costs, and injection resistance.
- **Sequence findings now cross-reference Sigma correlation rules end-to-end**
  — `DetectionMatcherAgent.match_for_finding` / `match_for_sequence` map a
  correlated finding's pattern (`brute_force`, `auth_failure_then_success`) to
  the ATT&CK techniques describing it and return only Sigma **correlation**
  rules covering those techniques — a base single-event rule that merely
  shares the tag is never presented as covering a multi-event pattern.
  Matches carry the pattern they cover, deduplicate across findings, and rank
  most-severe first. The orchestrator's `process_sequence` attaches them
  (`sequence_detections`), the incident report gains a "Matching Detections"
  subsection under Sequence Correlation, and the dashboard batch tab renders
  them — closing the loop between sequence triage and detection engineering,
  the way single events already close it via `match_for_event`. Deterministic,
  read-only, fail-soft (unknown patterns and malformed findings yield no
  matches); pinned by five new tests against the real corpus.

### Changed
- **Generated docs 00-09 refreshed to v2 reality** — the numbered root docs
  (architecture, roadmap, agent blueprints, environment setup, governance
  rules, portfolio tracker, first-build sprint, Codex review workflow,
  master blueprint) plus the adjacent generated docs (dashboard concept,
  12-month roadmap, operator workflows) had been untouched since the initial
  Master v1 scaffold. Their templates in `generate_docs_from_design.py` now
  describe the shipped v2.0.0 platform: all eight blueprints built (with the
  supporting agents), sequence correlation, verified citations,
  embedded-by-default Qdrant, policy/audit enforcement, Codespaces setup
  path, and the enhancement-not-new-surface build stance. Roadmaps mark
  completed cycles honestly instead of presenting finished work as plans.
- **Doc generator no longer overwrites the curated README** — `README.md`
  removed from the generator's outputs; regenerating docs can no longer
  destroy the hand-maintained project README (this bit once — the exclusion
  is the permanent fix, documented in the generator's docstring).

### Security
- **PDF report pipeline hardened against injection and SSRF** — incident
  reports interpolate untrusted log content, and the Markdown → HTML →
  WeasyPrint path passed raw HTML through and fetched external resources
  during rendering. `scripts/convert_report_to_pdf.py` now (1) escapes
  `&`/`<` *before* Markdown rendering, so embedded markup (`<script>`,
  `<img src=…>`) becomes inert visible text while every report construct
  (headings, tables, fences, inline code) renders unchanged, and (2) renders
  with a **deny-all URL fetcher** (`base_url=None`), so report content can
  never trigger network requests (blocks metadata-endpoint SSRF, exfil
  beacons, `file://` reads). Renderer imports are lazy; the controls are
  pinned by `tests/security/test_report_pdf_hardening.py`.
- **Audit artifacts created owner-only** — the tamper-evident audit log's
  active file, rotated segments, `.checkpoint` sidecar, and head signature
  are now created `0o600` (directory `0o700`) regardless of the process
  umask; permissions of pre-existing files are deliberately never rewritten
  (operator-chosen schemes are respected). Pinned by
  `tests/security/test_audit_file_permissions.py`.
- **Dashboard input bounds** — server-level upload cap
  (`.streamlit/config.toml`: `maxUploadSize = 10` MB, down from Streamlit's
  200 MB default) plus a 2,000-line batch cap with a visible truncation
  notice — defense in depth against oversized or malicious batch uploads.

### Security
- **CI supply-chain hardening** — every GitHub Action across all five
  workflows (31 references, 12 distinct actions) is now pinned to a full
  commit SHA with a human-readable version comment (immune to tag-rewrite
  attacks; Dependabot keeps updating the pins). Every `actions/checkout` sets
  `persist-credentials: false` — no job in this repo pushes with checkout
  credentials, so none keeps a write-capable token on disk. Pre-commit now
  mirrors CI more faithfully: bandit gains the `mcp` scope, mypy covers the
  full CI scope, and the stdlib-fast drift gates (rename guard, status-page
  sync) run locally before commits reach CI.
- **Repo hygiene: generated third-party content untracked** —
  `node_modules/` (45 MB, 6,750 files) and `qdrant_storage/` (Qdrant server
  state) removed from git and gitignored; the dependency set remains fully
  captured by `package-lock.json` + the attested npm SBOM, and vector
  collections regenerate from `knowledge-base/` via the ingest scripts.
- **Qdrant embedded-by-default** — new `rag/qdrant.py::make_client()`
  consolidates ten hardcoded `localhost:6333` client sites; with
  `QDRANT_URL` unset the client runs **in-process** (vectors under
  `QDRANT_PATH`, default `./data/qdrant`) with **zero listening ports** —
  no service, container, or daemon. Setting `QDRANT_URL` opts in to a
  server (compose lab stack). Semantic KB search now works in Codespaces
  and minimal installs; keys documented in `.env.example`.
- **Secret-scanning baseline committed** — `.secrets.baseline`
  (detect-secrets 1.5.0) makes the pre-commit hook enforce; the two
  baselined findings were human-reviewed and are false positives (the
  policy engine's `secret_handling` action-class labels, not credentials).
  A repo-root `.gitleaks.toml` (default rules extended) allowlists the
  baseline file by path: its SHA-1 digests of the reviewed strings trip
  gitleaks' generic-api-key rule, so without it the two secret scanners
  fight — one's allowlist is the other's "leak". Digests of non-secrets
  are unrecoverable; real secrets anywhere else are still caught.

## v2.0.0 — Master v2 STICHES Edition: the IANUA identity era

**Milestone: the platform is IANUA everywhere (repo, docs, Pages, dashboard,
SBOM), the SOC pipeline correlates sequences end-to-end from agents through
reports to the dashboard, retrieval is rarity-weighted with verified passage
citations, audit verification produces located forensics, and the whole
platform is testable from a browser in one click. Edition identity advances
to Master v2 STICHES; every agent reports v2.0.0 automatically via the
pyproject-derived version.**

### Changed — foundations refreshed for v2
- **Charter (`AGENTS.md`) brought current** — the §4 layout tree now maps the
  real repository (dashboard, knowledge-base, security/sbom, devcontainer,
  portfolio, sample-logs…); §7 gate commands match CI's exact scopes
  (`mypy agents scripts tests dashboard mcp rag`,
  `bandit -c pyproject.toml -r agents scripts mcp`, plus the drift-gate
  checks); §8 documents the pipeline as it exists (CodeQL, dual-Python tests,
  sandbox enforcement, read-only drift gates, and the **human-gated Pages
  deploy, kept by design**). `CLAUDE.md` follows via symlink.
- **Security policy consolidated and updated for v2** — root `SECURITY.md` is
  the canonical policy (supported versions 2.0.x; components-in-scope table
  covering the policy/audit layer, sandbox, dashboard, detections, and
  verification CLIs; the full current control set: SAST+CodeQL, SCA+SBOM
  drift gates, secret scanning, tamper-evident audit with signing, sandboxed
  tool execution, least-privilege CI, human-gated deploys).
  `.github/SECURITY.md` is now a pointer with the private-reporting
  essentials, so the two copies can never diverge again.
- **`DESIGN.md` module map completed** — dashboard, knowledge-base, and
  security/sbom rows added with their invariants.

### Security
- **gitpython bumped 3.1.50 → 3.1.54** (transitive, via streamlit) — clears
  GHSA-2f96-g7mh-g2hx, GHSA-v396-v7q4-x2qj and GHSA-956x-8gvw-wg5v (all fixed
  in 3.1.51), which were failing the CI `pip-audit` SCA gate. `uv.lock` is the
  source of truth; derived pip locks, `python.cdx.json` and the merged SBOM
  were regenerated (`pip-audit` now reports no known vulnerabilities; lock and
  SBOM drift gates verified in sync).

### Added
- **One-click interactive test environment (GitHub Codespaces)** — new
  `.devcontainer/devcontainer.json`: from the repository page (Code →
  Codespaces → Create) the container installs `.[dev,dashboard]`, auto-starts
  the Streamlit dashboard, and forwards port 8501 (private to the owner), so
  every feature is testable in the browser with zero local setup. GitHub Pages
  is static and cannot run the app; this is the supported "test it from
  github.com" path (documented in the README Quickstart).
- **Bundled sample scenarios in the Batch tab** — a fixed allow-list of
  deterministic fixtures from `sample-logs/` (SSH brute force,
  failures-then-success) loadable without preparing an upload, so sequence
  correlation, verified citations, and the incident report are one click away.
- **Knowledge-base search fails soft** — `search_kb_resilient()` tries the
  Qdrant semantic backend and degrades to the offline lexical
  `KnowledgeBaseAgent` corpus when Qdrant/embeddings are unavailable, with the
  serving backend labelled in the UI (degraded results are never passed off as
  the primary path). Heavy imports are now lazy, so the dashboard starts on a
  minimal install. Covered by `tests/unit/test_kb_search.py`.

### Changed
- **Dashboard batch flow upgraded to the correlated sequence pipeline** — the
  Streamlit "Batch Processing" tab now runs `OrchestratorAgent.process_sequence`
  once over the uploaded log (one deterministic pipeline run) instead of N
  independent per-line `process_log` calls that could not see multi-event
  patterns. The tab surfaces the sequence verdict (severity, score, event
  count, summary), the **Correlated Findings** (pattern, source, severity,
  contributing event numbers), a per-event breakdown table (now including the
  extracted source), sequence-wide threat intelligence, the **verified cited
  passages** with char offsets, and the generated sequence incident report.
  Empty uploads get a friendly warning instead of the pipeline's fail-closed
  exception surfacing as a traceback.

### Fixed
- **`sigma_eval` now supports `endswith`** — the modifier nearly all published
  endpoint Sigma content is written against (`Image|endswith: '\\cmd.exe'`).
  Its absence made such a rule raise rather than match: loud, but unusable.
- **OCSF class 1008 is Event Log Activity**, not File System Activity (that is
  1001). The uid on the `log tampering` mapping was always right; only the
  label was wrong.
- **IANUA rename completed; rename tooling repaired** — `scripts/rename_to_ianua.py`
  no longer rewrites or scans its own source (its `REPLACEMENTS` table contains
  the legacy identifiers by design, so `--apply` used to collapse the table to
  identity mappings and `--check` then flagged every occurrence of the *new*
  name — the workflow could never pass). The script now excludes itself and
  local cache directories (`.mypy_cache`, `.pytest_cache`, `.ruff_cache`,
  `__pycache__`, `htmlcov`), and is `ruff format`-clean (the unformatted file
  was failing CI static analysis for every PR). The remaining legacy
  pre-IANUA project identifiers across docs, detection content, dashboard, scripts, the status
  page, and SBOM metadata were migrated with the fixed script (deterministic,
  idempotent; `--check` is clean and drift gates — status page, SBOM, locks —
  stay green).
- **Canonical repository identity across the Pages site and dashboard** —
  the GitHub Pages landing (`docs/index.html`) now links to the renamed
  repository with its canonical casing (`github.com/IRsoctierDT/IANUA`,
  including the clone/`cd` quick-start snippet); two identity strings that the
  line-based migration missed because they were **wrapped across lines**
  (`detections/README.md`, the AGENTS.md closing charter) are fixed by hand;
  the status page tagline and the Streamlit dashboard caption now describe the
  IANUA platform (SENTINEL remains the landing page's design wordmark only).
  Status page regenerated in sync.
- **Rename workflow converted to a least-privilege guard** — the
  `Complete IANUA rename` workflow no longer checks out a fixed side branch
  with `contents: write` and auto-pushes; it now runs a read-only
  `rename_to_ianua.py --check` against the ref under test on every PR (same
  check name, so branch protection is unaffected), failing only if a legacy
  identifier is reintroduced.

### Added
- **Deepened audit-verification tooling** — `AuditLogger.verify_report()`
  returns a structured diagnosis instead of a bare bool: entry/segment counts,
  chain head, checkpoint anchor, granular head-signature status
  (`valid`/`invalid`/`stale`/`missing`/`malformed`/`unsigned`/`empty`), and —
  on failure — the first broken segment, line, and kind of break. Malformed or
  corrupted entries are now a located fail-closed *verdict* (previously the
  verifier raised on garbage lines). `verify()` is unchanged in behaviour (thin
  wrapper). New standalone `scripts/audit_verify.py` CLI: read-only chain +
  signature verification for cron/CI/auditors, auto-detecting `AUDIT_HMAC_KEY`
  or the Ed25519 **public-key-only** `AUDIT_ED25519_PUBLIC_KEY` scheme, with
  `--require-signature` to refuse chain-only verification (exit codes 0/2/3).
- **Report enrichment: sequence findings + verified passage citations** —
  incident reports gain a "Sequence Correlation" section (multi-event findings
  from `SocAnalystAgent.analyze_sequence`: pattern, source, severity,
  contributing events) and a "Cited Passages" section quoting the exact
  grounding passages with char-offset locators — labelled "(verified)" only
  when the caller attests that `verify_citations` passed
  (`citations_verified=True`; the report agent never mislabels unchecked
  citations). The orchestrator now
  attaches passage-level citations to `process_log` **only after they pass the
  anti-hallucination check** (`verify_citations`; unverifiable citations are
  dropped, fail-closed), and gains `process_sequence(events)` — the full
  pipeline over an ordered batch: sequence correlation, standard sections
  anchored on the most severe event, threat intel over the sequence-wide
  indicator union. PDF export inherits both sections automatically.

### Changed
- **RAG retrieval precision: rarity-weighted (IDF) lexical scoring** — the
  Knowledge Base Agent's lexical mode and the citation engine's passage
  selection now weight query terms by corpus/document rarity
  (`log1p(N/(1+df))`) instead of counting every term equally. Discriminative
  terms ("kerberoasting") outrank ubiquitous ones ("security") rather than
  tying and falling back to alphabetical/document order. Deterministic,
  dependency-free, same [0, 1] semantics (all-terms match still scores 1.0;
  uniform rarity reduces exactly to the previous fraction). Applies to
  `retrieve()`, `cite()`, and `best_passage()`.

### Added
- **Detection content: five new Sigma rules** (`detections/sigma/`) covering
  gaps in the agent vocabulary — `firewall_block` (base) +
  `firewall_block_burst` (≥20 blocks/source/5m — port-scan correlation, the
  SOC agent's `firewall block` event type finally has content),
  `linux_account_added_to_privileged_group` (T1098) +
  `account_created_then_privileged` (create-then-privilege chain correlation,
  critical), and `linux_command_history_cleared` (T1070.003 defense evasion).
  The existing account-creation rule gained a `name:` so chains can reference
  it. All structurally validated by `tests/test_detections.py`; the Detection
  Matcher Agent picks them up automatically via ATT&CK tags.
- **SOC Analyst Agent: multi-event sequence correlation**
  (`SocAnalystAgent.analyze_sequence`) — correlates an ordered batch of log
  events into findings a single-line analysis cannot see: **brute force**
  (≥3 authentication failures from one source; `critical` when a privileged
  account is targeted) and **possible credential compromise** (failure
  followed by a successful login from the same source; always `critical`).
  Deterministic, fail-closed input validation, no network activity —
  an enhancement of the existing agent, no new surface. Duplicated
  privileged-account logic consolidated into one helper.

### Changed
- **Agent versions now track the platform automatically** — `agents.__version__`
  resolves from `pyproject.toml` (the release source of truth; falls back to
  installed package metadata, then a conspicuous `0.0.0` sentinel), and every
  named agent derives its display name via `agents.versioned_agent_name()`.
  The SOC Analyst Agent — stuck announcing `v0.2` since the platform hit
  `v1.9.0` — and all six other named agents now report
  `"<Agent> v<platform version>"` and update on every release without manual
  edits. A drift-gate test (`tests/unit/test_agent_versioning.py`) fails the
  build if any agent hard-codes a version again.

### Fixed
- **GitHub Pages deploy failing with "No artifacts named github-pages were
  found"** — the split build/deploy design uploaded the site artifact in the
  build job, then the deploy job waited on the `github-pages` required-reviewer
  gate. When approval came later than the Pages artifact's ~1-day retention, the
  artifact had expired and the deploy failed. Combined build + deploy into a
  single environment-gated job so approval holds the whole job and, once
  approved, the artifact is built, uploaded, and deployed fresh in one shot. The
  human approval gate is unchanged; only the structure that made an approved
  deploy fail was fixed.

## v1.9.0 — Hardening #2: tamper-evident audit, sandboxed tools, verifiable RAG

**Milestone: the policy/audit layer is enforced at the tool surface, tool
execution is containerized, the supply chain is attested end-to-end, and RAG
answers carry verifiable citations.**

### Added — policy & audit
- **Policy engine + tamper-evident audit log** — default-deny action
  classification (AGENTS.md §5.1 approval gates codified), enforced at the MCP
  tool surface via a shared policy-guard primitive; declarative policy bundle
  loader with a staged report mode; the AGENTS.md §6 operating roles codified.
- **Audit-log hardening series**: tamper-evident rotation & retention;
  HMAC head-hash signing; asymmetric **Ed25519 signing** via a pluggable
  `Signer`; on-demand retention plus a scheduled maintenance CLI.

### Added — sandboxed tool execution
- **Rootless seccomp/AppArmor container sandbox** for MCP tool execution, with
  digest-pinned image guard and per-tool profiles.
- **Real-container CI enforcement job** (`Sandbox enforcement (Linux
  container)`) with non-vacuous tests.

### Added — RAG & reporting
- **Verifiable passage-level source-citation engine** — every retrieved claim
  cites the passage it came from.
- **Persistent SQLite vector store** (`rag/` now in the mypy gate).
- **Local-LLM narrative generation** (opt-in → on-by-default): Ollama and
  llama.cpp backends, **GBNF grammar-constrained** structured output.
- **PDF export** for incident reports (reportlab, pure-Python).
- Sigma **detection rules, correlations, and structural validation** wired into
  the SOC pipeline (detection coverage in reports).

### Added — supply chain & CI
- **CycloneDX SBOM** (Python + npm, merged, purl-complete) with vulnerability
  triage; **Sigstore-signed SBOM** and **SLSA build-provenance attestations**
  on every main build.
- **`uv.lock` as dependency source of truth**; hash-pinned dev toolchain
  installed under `--require-hashes` in CI; lock/SBOM **drift gate**
  (`sbom-sync`) fails closed.
- **Deterministic lock regeneration** (`scripts/refresh_locks.py`) — constrains
  resolution to `uv.lock`'s exact pins with PEP 508 marker evaluation.
- **Daily scheduled SCA scan** of the committed lock on main
  (`security-scan.yml`) so advisory decay is detected within a day.
- **Dependabot**: daily GitHub Actions cadence; grouped uv/npm updates;
  **auto-merge for low-risk groups only** (dev-toolchain, actions — patch/minor,
  gated on required status checks). Branch ruleset requires the 7 core CI
  checks before merge.
- **Property-based fuzzing** of tool input validators (`tests/security`).

### Added — site & docs
- **Command Center status page** (`scripts/build_status_page.py`) — a
  deterministic, offline generator that renders `docs/status.html` and
  `docs/status.json` from one committed source of truth (`docs/status.data.json`).
  Input is schema-validated and fails closed on unknown status tokens; every
  dynamic field is HTML-escaped as defense in depth (covered by
  `tests/security/test_status_page_escaping.py`). Linked from the site nav.
- **CI drift gate** (`status-page-sync`) — fails the build if the committed
  status page drifts from its source data, mirroring the SBOM/lock sync gates.
- **GitHub Pages landing site** with automated (human-approved) deploy;
  dashboard **Command Center UI** (Mission Control, Agent Roster, Activity
  Timeline); **nine component case studies** + hardening roadmap; local lab
  `docker-compose` stack.

### Fixed
- **GitHub Pages deploy deadlock** — the Pages deploy is split into isolated
  build/deploy jobs and now uses `cancel-in-progress: true`, so a run left
  `waiting` on the `github-pages` environment approval can no longer hold the
  concurrency slot and jam every later deploy. The required-reviewer approval
  gate is kept intentionally (human-in-the-loop for deploys, AGENTS.md §5.1);
  only the concurrency defect was fixed. Manual `workflow_dispatch` publishes
  are restricted to `refs/heads/main` so a run can't publish `docs/` from an
  untested branch.
- **Advisory clean-up**: pillow 12.3.0 (PYSEC-2026-2254/-2256/-2257),
  setuptools 83.0.0 (PYSEC-2026-3447), torch 2.13.0 (PYSEC-2025-194) — the
  committed closure audits to **0 known vulnerabilities** at release time.
- SBOM made attestable (CycloneDX `serialNumber`); CI restored on main after an
  invalid workflow file + `uv.lock` drift.

### Quality
- Test suite expanded to **390 passing** (4 environment-gated skips); ruff +
  mypy + bandit green across `agents`, `scripts`, `tests`, `dashboard`, `mcp`,
  and `rag`; coverage gate ≥85% enforced in CI.

## v1.8.0 — Agent suite complete

**Milestone: all eight agent blueprints from `03_Agent_Blueprints.md` are built.**

### Added
- **Knowledge Base Agent** — grounds incident reports in the curated cybersecurity
  corpus; deterministic term-overlap retrieval, wired into the orchestrator and the
  incident report ("Knowledge Base References" section).
- **Opt-in semantic retrieval** for the Knowledge Base Agent (`mode="semantic"`):
  local-embedding cosine ranking via the loopback-only, fail-closed `OllamaEmbedder`,
  with automatic fallback to lexical when Ollama is unreachable.
- **Vulnerability Assessment Agent** — ranks authorized scan findings into a
  remediation priority order (no scanning; unrated findings stay "unknown").
- **Legal/Compliance Research Agent** — triages a legal inquiry into a
  verify-don't-assert authority checklist (no advice, no fabricated citations).
- **Business Proposal Agent** — structures client needs into a reviewable
  proposal / SOW draft (drafts only, no invented pricing).
- **Knowledge Curator Agent** — organizes raw notes into retrieval-ready KB entries.
- **Portfolio Documentation Agent** — drafts READMEs/case studies in the AGENTS.md
  §9 structure.
- **Executive Assistant Agent** — prioritizes tasks/notes into a reviewable plan
  with blockers and a decision-log template.
- **SOC Analyst Agent v0.2 case study** (`docs/case-studies/`).
- Expanded, **source-cited** cybersecurity knowledge base (OWASP Top 10:2025,
  MITRE ATT&CK, NIST CSF 2.0, CIS Controls v8.1, Security+ SY0-701, SOC).

### Changed
- Dashboard SOC tab shows a severity metric and surfaces KB references; dashboard
  dependencies declared (`pip install -e ".[dashboard]"`) and added to the mypy gate.
- `OrchestratorAgent.process_log` takes an explicit `report_path` (test isolation).
- CI hardened: gitleaks `pull-requests: read`, CodeQL v4 + `actions: read`, all
  GitHub Actions bumped to Node 24-native versions; `SECURITY.md` refreshed.

### Quality
- Test suite expanded to **135 passing**, **~93% coverage**; ruff + mypy + bandit
  green across `agents`, `scripts`, `tests`, and `dashboard`.

## v1.7.0
- Fix dashboard health panel integration

## v1.6.0
- Add dashboard knowledge base search

## v1.5.0
- Add category-filtered knowledge base search

## v1.4.0
- Expand chunked ingestion across the full knowledge base

## v1.3.0
- Expand cybersecurity knowledge base sources

## v1.1.0
- Add dashboard documentation and screenshot checklist

## v1.0.0
- Add v1 usage guide and release notes

## v0.9.0
- Add batch log processing CLI

## v0.8.0
- Add CLI runner for incident workflow

## v0.7.0
- Add orchestrator agent

## v0.6.0
- Add PDF incident report generation

## v0.5.0
- Added Threat Intelligence Agent
- Added indicator classification
- Added threat intelligence test suite

## v0.4.0
- Added MITRE Mapper Agent
- Integrated MITRE ATT&CK mapping into incident reports

## v0.3.0
- Added Incident Report Agent

## v0.2.0
- Added chunked RAG pipeline

## v0.1.0
- Initial local AI stack
