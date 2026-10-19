# Changelog

All notable changes to this project. Versions correspond to git tags.

## Unreleased

### Added
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

### Changed
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

### Added
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

### Fixed
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

### Fixed
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

### Fixed
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
  count equal, digest equal, **exit 0**. Indicator pivots return nothing on such
  a store, because `correlation/entities.py` joins on that table. The number was
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

### Changed
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
