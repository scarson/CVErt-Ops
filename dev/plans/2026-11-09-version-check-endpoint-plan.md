# Version check endpoint: implementation plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (or superpowers:executing-plans) to implement this plan task-by-task. Do not start until the **Plan review** line below has been completed.

**Goal:** Ship `POST /api/v1/orgs/{org_id}/check` (requirement MATCH-1): for a list of exact component versions, say which advisories affect each one, which range matched, and what version fixes it.

**Architecture:** Two pull requests with a full ingest between them. Phase 1 changes what is stored (`package_key`, the union of CNA copies, NVD `caught_up`, four lookup indexes). Phase 2 runs a full live ingest on that code. Phase 3 adds pure verdict code in `internal/check`, a snapshot read in `internal/store/check.go` and the handler in `internal/api/check.go`, built while the ingest runs. Phase 4 measures the endpoint on the ingested corpus before Phase 3 merges.

**Tech Stack:** Go 1.26, PostgreSQL 15+, sqlc, chi with huma spec-only registration, `github.com/package-url/packageurl-go`, `github.com/google/osv-scalibr/semantic`, testcontainers.

**Design:** `dev/plans/2026-11-08-version-check-endpoint-design.md`, approved by Sam on 2026-11-09. It is the authority for every verdict rule, and tasks cite its sections instead of repeating them. If this plan and the design differ on behaviour, stop and ask Sam, and record what he accepts under Deviations.

---

## Living Document Contract

This plan is a living document. Every executing agent MUST update it as
execution progresses, not only at completion.

Where this project has no git repository, every reference below to a SHA,
a branch, or a PR means the nearest durable equivalent the project does
offer (a dated revision, a build identifier, a release tag), and where
none exists the banner states that plainly. An invented SHA is worse than
an absent one: it reads as an anchor and sends the next agent looking for
a commit that never existed.

- **Before any phase claim:** no phase may be claimed while the
  **Plan review** line in Execution Status reads ⬜ NOT RUN. An unreviewed
  plan is not executable. Run the review (`plan-review-cycle`) and let its
  completion flip the line, or — if this plan was legitimately exempted by
  the user — record that at the line as ⏭ SKIPPED with the date, so the
  exemption is visible instead of indistinguishable from an omission. A
  line still reading ⬜ at execution time means the gate was skipped
  silently, which is the one state this record exists to make impossible.
- **On phase claim:** before flipping your own banner, the executor MUST
  check the preceding phase's banner against git reality — a ✅ SHIPPED
  banner's recorded SHA reachable on `dev`, this project's integration branch, a 🚧 banner live
  per the stale-claim signals below. If a banner does not match reality,
  correct it first. A plan's accuracy is checked by the next agent to
  arrive, not by the one who left it; this is the only read-back the
  contract has. Then flip your own banner to 🚧 IN PROGRESS
  with a claim timestamp (ISO 8601 UTC) and the active branch name. The
  banner MUST NOT include an expected-completion estimate — agents cannot
  reliably estimate their own wall-clock, and a fabricated duration
  becomes a stale anchor that misleads future readers. Followers
  encountering a 🚧 banner determine liveness by observable signals (PR
  existence, recent branch commits), not by arithmetic on expected times.
  See `/writing-plans-enhanced` §Plan construction requirements for the
  stale-claim reclaim protocol.
- **On phase ship:** the executor MUST update that phase's **Execution
  Status** banner with the shipped commit SHA(s) and date. If a PR is
  open, the PR number and URL MUST appear in the Execution Status table.
  Recorded SHAs stay resolvable because this project merges with
  `--merge` and preserves per-commit history; under a squash-merge
  workflow, record the squashed commit that landed on `dev`, this project's integration branch
  instead, or the banner points at a SHA no reader can find.
  **The banner ships in its own commit, after the work.** A commit
  cannot contain its own hash, so the banner naming a SHA cannot ride
  in the commit that SHA identifies. Commit the work with a pathspec
  that excludes this plan, read the SHA back from git, then commit the
  banner and table update on top. Amending is not a way out — it
  rewrites the SHA you just recorded. Where the phase ships through a
  PR, **On PR merge** below is a second such update for the same
  reason, and lands after the merge.
- **On phase defer:** the executor MUST update the banner with ⏸ status
  AND a prose description of the unblock condition + a link to the
  likely-unblocker artifact (plan page, task, or PR whose own Execution
  Status banner will signal completion). Prose + link is durable across
  paraphrases and scope edits; exact-string coordination between agents
  is not.
- **On PR merge:** the executor MUST record the merge SHA in the banner
  + the Execution Status table.
- **On deviation from the written plan** (scope edits, structural
  refactors, dropped tasks, reordered phases): the executor MUST
  inline-document the deviation in the affected task AND summarize it
  in the Execution Status section's "Deviations" subsection.
  Deviation state MUST NOT live only in PR notes or status reports.
- **On discovery** (pre-existing drift surfaced during execution, new
  bugs found, architectural issues noted): the executor MUST record it
  in the Execution Status section's "Discoveries" subsection with
  pointers to the files/lines affected. Follow-up dispatches read this
  subsection to avoid duplicate discovery work.

**Layout invariant.** Only the two one-line headers — **Plan review** and
**Overall** — sit above the status table; the table follows them directly.
Deviations and Discoveries are subsections
*below* it and MUST NOT be placed above it — the table is what a reader
needs in the first screen, and it stops being that the moment a growing
narrative sits on top of it. Entries in both subsections are a one-line
summary plus a pointer to where the detail lives (the affected task, the
file:line); they are not the place to tell the story.

The plan SHOULD reflect reality at the end of every session that touches
it. Anything worth putting in a status report to the user is worth
putting in the plan.

Rationale: `/writing-plans-enhanced` §Plan construction requirements.
Writing at ship time is
cheap; reconstruction by downstream readers is expensive, compounds
across dispatches, and fails silently when state is split across PR
notes and commit messages.

---

## Execution Status
<!-- Plan review and Overall are the only lines above the table. New content goes
     in the Deviations / Discoveries subsections below it — never above the table. -->

**Plan review:** ⚠️ TERMINATED-FOR-EXECUTION 2026-11-09 — 8 rounds, 5 verify-first flags annotated in place
**Overall:** Phase 1 shipped to `dev` (merge `45357f5`). Phase 2 (full ingest) is done (2026-11-12). Phase 3 (endpoint) and the Phase 4 changes shipped to `dev` in [PR #218](https://github.com/scarson/CVErt-Ops/pull/218) (merge `d6919bf`, 2026-11-12). Phase 4 is done: the go/no-go run (2026-11-12) led to the roll-up and Ubuntu changes (Deviations), and the index write cost was measured on 2026-11-13 (Phase 4 notes).

| Phase | Status | Ship SHA(s) | Notes |
|---|---|---|---|
| 1 — Data changes | ✅ Shipped 2026-11-10 | Merge `45357f5` on `dev`. Tasks: `2018ce4` (purl mapping), `c79cd32` (package key and indexes), `80c273b` (every CNA copy), `356bf6e` (NVD `caught_up`), `397a8c3` (`PLAN.md`). Review fixes: `ac5ad2b`, `7882fef`, `2899441`, `b741212` | Branch `claude/check-data-72f424`. [PR #213](https://github.com/scarson/CVErt-Ops/pull/213). Lint clean and full suite passed at `b741212` |
| 2 — Full ingest | ✅ Done 2026-11-12 | No code. Worker builds: `2c9fac0`, `4356557`, `f663fd7`, `f56bde0` | Completion signals met 2026-11-12 06:56 UTC. Fixes found during the ingest: [PR #217](https://github.com/scarson/CVErt-Ops/pull/217), [PR #221](https://github.com/scarson/CVErt-Ops/pull/221), [PR #222](https://github.com/scarson/CVErt-Ops/pull/222). Measurements in Phase 4's notes |
| 3 — Endpoint | 🚧 PR open 2026-11-10, awaiting Phase 4 | Task 3.1 `74b5011`, Task 3.2 `a9f86cf`, Task 3.3 `e7d2e87`, Task 3.4 `ae67ed3`, Task 3.5 `d251fe2`, review fixes `6e54c4d`, `7b5b880`, `8cf9c18`, `6618ae4`, `66a4091`; Task 3.6 `ac983d0`; Task 3.7 `cc2c772`; Task 3.8 `a6a97ce`, `4d31bda`; Task 3.9 `df55220`; Task 3.10 `6e8f968`; Task 3.11 `efd1df4`. Phase-end review fixes: round 1 `3781bec` to `3d8243a`, round 2 `b4a1e86` to `a4fa730`, round 3 `378ccbc` to `a72bd84`, round 4 `238ba4b`, `86d5578`. Head `5c4e025` | Branch `claude/check-endpoint-734a7a`. [PR #218](https://github.com/scarson/CVErt-Ops/pull/218) to `dev`, unmerged until Phase 4 reports. Lint clean and full suite passed at `5c4e025` |
| 4 — Measurement and merge | ✅ Done 2026-11-13 | `0241f0d`, `d6919bf` | Branch `claude/check-endpoint-734a7a`. Go/no-go run on the complete ingest at `7dae4bf`: every current release answered `cannot_evaluate`. Two independent reviews, at Sam's instruction, agreed the changes built in `0241f0d`; re-measured on the copy (Phase 4 notes). PR #218 merged to `dev` as `d6919bf`. Index write cost: smaller than run-to-run variation (Phase 4 notes) |

### Deviations

- Phase 1 runs on branch `claude/check-data-72f424`, the worktree branch the executing session was given, not `feat/check-data`. See Phase 1's banner.
- Task 1.1: `FromPurl` refuses more than the plan's code. It refuses invalid UTF-8 and U+FFFD with `invalid_purl`. It refuses major release numbers (and any of Alpine's numbers) with leading zeros, and Ubuntu releases without a two-digit month, with `distro_not_recognised`. Both refuse in the safe direction, found in the Phase 1 review. See the note under Task 1.1.
- Task 1.2: `ParseCNAAffected` keeps an entry whose only identity is its `packageURL`, and the two golden CNA tests expect the key. See the note under Task 1.2.
- Phase 3 runs on branch `claude/check-endpoint-734a7a`, the worktree branch the executing session was given, not `feat/check-endpoint`. See Phase 3's banner.
- Task 3.1: `internal/version/check.go` also changed. A `scheme.order` method validates both sides before comparing, and `Check` and `Compare` share an `ecosystemScheme` helper, so each syntax gate is written once. `Compare`'s errors are unchanged. Commit `74b5011`.
- Task 3.2: `ParseItem` also refuses invalid UTF-8 as `invalid_characters`, and compares a CPE's own version with the `version` field without regard to case (the CPE is lower-cased, the field is not). Commit `a9f86cf`.
- Task 3.4: the combining rule of design section 4.1 is one helper, `rowVerdicts` in `internal/check/verdict.go`, which package and CPE rows share; `reasonFor` moved there. CPE shapes the design does not describe answer `invalid_range`: a CPE that is not 13 components, both `versionStart*` bounds set, and a literal version component with bounds. Commit `ae67ed3`.
- Task 3.5: `Matched` for a CNA entry holds the segment that contains the version (start as `introduced`; end as `fixed` when exclusive, `last_affected` when inclusive), so `reading` carries the segment. Commit `d251fe2`.
- Task 3.5, shapes design section 4.3 does not cover, each read towards Indeterminate under "Rules for every task" (focused review of `internal/check/cna.go`, commits `6e54c4d`, `7b5b880`, `8cf9c18`):
  - A single-version line wildcard such as `{8.1.*, affected}` is the segment `[8.1, 8.2)` with a wildcard end: `8.1.5` Indeterminate, `8.2.0` No statement. Normalising the lower bound first, as the plan's text reads, made it `[8.1, 8.1]` and read `8.1.5` as No statement.
  - `.x` and `.X` line wildcards (`2.x`, `2.4.X`) are read like `.*`. Maven and RPM can parse `2.x` as a version, so `{1.0, lt 2.x, affected, maven}` read `2.5` as No statement. Any other value ending in `.*`, `.x` or `.X` is unreadable.
  - A segment that is not `unaffected` and whose end is below its start (or equal with an exclusive end) makes the entry Indeterminate for every version, as `version.validateRange` refuses the same shape. A zero-length segment counts only when it is the last one, so a change at the entry's own lower bound does not block it (`6618ae4`). Before, `{2.0, lt 1.0, affected}` and a change to `affected` above `lessThan` read No statement everywhere.
  - Changes at one version collapse to one change, with status `unknown` when their statuses differ. In input order, `[{2.0, affected}, {2.0, unaffected}]` read `2.0` as No statement or Affected, depending on order.
- **For Sam (Task 3.5):** a lower bound of `*` with an upper bound, such as `{*, lte 1.4.4, affected, semver}`, reads Indeterminate at or below `1.4.4`, because the design normalises only `8.1.*`-style bounds. Reading a bare `*` lower bound as `0` would give Affected. It cannot clear a version either way. The review believes Wordfence writes this shape; Phase 4 can count it.
- Task 3.6: `Combine` step 4 also requires `primary.Comparable` (no effect on outcomes `rowVerdicts` builds). `NamesFor` removes CPE backslash escapes when it turns a CPE vendor or product into a CNA name (`foo\:bar` looks up `foo:bar`); the table stays keyed by the CPE's spelling. `CNAName.Matches` lower-cases both sides, as SQL `lower()` does. Commit `ac983d0`.
- **For Sam (Task 3.6, `internal/check/names.go`):** design section 4.5's prefix `.net ` also matches a CNA product `.NET Framework 4.8`, so .NET Framework entries are read when checking `microsoft:.net`. Their versions are 4.x, so they can affect only a 4.x check. A test documents it.
- Task 3.7: `fix_major` also skips one leading `v` (Go module versions) and a PEP 440 epoch (`1!`), as well as a dpkg or RPM epoch. Commit `cc2c772`.
- Task 3.8 (commits `a6a97ce`, `4d31bda`):
  - `evaluate.go` is split into `keys.go`, `results.go` and `evaluate.go`.
  - `Limits` with `DefaultLimits` and `EvaluateWithLimits`, so tests can lower the item and advisory limits.
  - `Evaluate` refuses `Candidates` whose slices do not match `KeysFor(items)`, because a missing key would read as no rows.
  - An item with no form is `invalid_form`.
  - Nearby-name rows override every advisory verdict except Affected, including `too_many_ranges`.
  - Top-level `feeds` are sorted by name.
  - The store task's implementation-log file was committed inside `4d31bda`, because two agents shared the worktree's git index.
- Task 3.9 (commit `df55220`):
  - Every null text column reads as `""`.
  - A row past a key's limit still counts towards the request's row and byte totals.
  - `export_test.go` exposes `ReadCheckCandidatesWith`, `CheckLimits`, `DefaultCheckLimits` and the two index expressions.
  - The CPE and CNA index pin tests asked for under Discoveries are `TestCheckCPEIndexMatchesQuery` and `TestCheckCNAIndexMatchesQuery`.
- Task 3.10 (commit `6e8f968`):
  - The handler writes `check.Results`. The `Check*` types are registered for the spec only, and `TestCheckResponseTypesMatchResults` keeps the two in step.
  - `Server.checkLimits` (default `check.DefaultLimits`) lets package `api` tests lower the item and advisory limits.
  - 503 when slots are full carries `Retry-After: 1`. 422 for the request limit uses problem type `urn:cvert:error:candidate_limit_exceeded`.
  - `items` also has `minItems: 1`.
  - `CheckComponent` and `CheckItemError` carry a blank `nullable` field, because huma refuses `nullable` on a `$ref`.
  - `securityFixture` (`openapi_security_test.go`) gained `api` and `db` fields for reuse.
  - The 422 request-limit path is tested by mapping errors directly (`TestWriteCheckFailure`), because the store limits cannot be lowered from package `api`.
- Task 3.11 (commit `efd1df4`):
  - The five "Table test" rows of design section 12 also run end to end.
  - "Mixed snapshot" is a skipped subtest that names `internal/store` `TestReadCheckCandidates_OneSnapshot`.
  - "`changes[]` must not clear" uses only the NGINX Open Source entry of CVE-2024-7347. The record's F5 / NGINX Plus entry is a nearby name for `f5:nginx` and would answer `cna_name_uncertain` whatever the Open Source entry says, hiding the rule from the break test.
  - The SeedCorpus count in `AGENTS.md`, `CLAUDE.md`, `README.md` and `dev/testing-pitfalls.md` is now 71. Existing golden pins did not move.
- Phase 3 review round 1 fixes (security review, pitfall check, plan check against `PLAN.md` §9.2; log `dev/implementation-log/2026-11-10T0801Z-check-endpoint-phase-end-review-fixes-round-1.md`):
  - `3781bec`: a CPE outside printable ASCII is `invalid_cpe`. Go and SQL lower-casing can differ outside ASCII, which would lose CNA rows silently.
  - **`1b60603`, for Sam, differs from design section 4.1:** a `SEMVER` row in an ecosystem with its own comparator is read by both orders: Affected if either says so, Not affected only if both do, otherwise cannot evaluate. Read as SemVer alone, as section 4.1 says, `Debian:13` `2.0.0-1` against `SEMVER [2.0.0, 3.0.0)` and Maven `1.0-sp` against `SEMVER [1.0, 2.0)` answered Not affected where the native order says Affected, against `PLAN.md` §9.2 ("MUST use the comparison rules native to the advisory's ecosystem"). Ecosystems with no comparator keep the SemVer-only reading. The design text was not edited; reverting is one function, `rowCheck` in `internal/check/packages.go`.
  - `81cd23e`: the handler reads, decodes and parses the body before it takes a check slot. It releases the slot before writing the response, and sets a 30-second write deadline. Before, a slow upload, or a client that stopped reading the response, held a slot, and four such clients blocked the endpoint for every org. The plan's Task 3.10 order took the slot first.
  - `0968e23`: a lookup past the request limit cancels its statement, rather than letting PostgreSQL stream the rest while `rows.Close` drains it.
  - `cf01f1c`: the store tests call `ReadCheckCandidates` directly. `3d8243a`: test comments call the CVE-2024-7347 entry the plan's simplified shape.
- Phase 3 review round 2 fixes (a review of the API and store, and an end-to-end search for a wrong "not affected"; log `dev/implementation-log/2026-11-10T0835Z-check-endpoint-phase-end-review-fixes-round-2.md`):
  - **`b4a1e86`, for Sam, extends design section 4.5:** each name-table row lists the CPE spellings it covers (`f5:nginx` with `nginx:nginx`, `microsoft:.net` with `microsoft:.net_core`). A CPE item with a table row reads NVD rows under every spelling, with its own part. The nginx row also gains CNA name `nginx` / `nginx` (design section 2, CVE-2017-7529). Before, `f5:nginx` `1.13.0` never read a CVE whose NVD rows are under `nginx:nginx` and could answer `not_affected`.
  - `f03fc7c`: a CPE vendor or product containing `_` is also looked up with `_` kept, and an unmapped CPE gets a second nearby-name key that keeps it. Before, a CNA product stored as `foo_bar` was matched by neither the name `foo bar` nor its fragment.
  - `327a6f6`: a backslash before `.`, `-` or `_` in a CPE vendor or product is removed, so `node\.js` reads NVD's `node.js`.
  - `da47312`: a PostgreSQL statement timeout (`57014`, 14 s by default) answers 503 like the 30-second check limit, not 500.
  - `7b670e6`: every lookup error cancels its statement before the rows are closed, and the five lookups `LEFT JOIN cves`, so a stored row with no `cves` row still counts towards a key's limit. The `LEFT JOIN` has no test, because merge cannot write such a row.
  - `48b48c4`, `393ef61`, `a4fa730`: tests pin the write deadline and the snapshot's isolation and read-only mode. The store reads the feed names from `check.FeedNames()`.
- Phase 3 review round 3 fixes (a review of the round 2 fixes; log `dev/implementation-log/2026-11-10T0856Z-check-endpoint-phase-end-review-fixes-round-3.md`):
  - `378ccbc`: a CPE's own CNA name is looked up in every mix of underscore spellings (vendor spaced or kept × product spaced or kept), and so are its nearby-name keys. Before, `acme_corp:foo_bar` never read a CNA row `Acme Corp` / `foo_bar`, and could answer `not_affected`.
  - **`c008d85`, for Sam, extends design section 4.5:** a nearby-name block is lifted by an NVD row under any vendor whose CPE spelling the item reads (its table row's vendors), not only the item's own vendor. Otherwise an `nginx:nginx` item stayed `cna_name_uncertain` for good on F5 CVEs with an NGINX Plus CNA row, while `f5:nginx` answered. The other side: an `f5:nginx` item's block is now also lifted by NVD rows under `nginx:*` (for example only `nginx:njs`), which falls under design section 4.5's accepted gap "NVD has analysed another product of the same vendor and missed this one".
  - Round 4 (a review of the round 3 fixes) found no wrong verdict. `238ba4b` adds a test that one key's vendor ranges cannot lift another key's nearby rows (a removed filter passed every test before). `86d5578` passes each key's own ranges in its own row, because the flat form scanned every key's ranges for each candidate row (46 ms to 2.2 s at 2,000 keys, measured with `EXPLAIN ANALYZE`). The controller read the round 4 diff and closed the review there.
  - `1644687`: a CPE vendor or product that is only an escaped `-` is `invalid_cpe`. `NamesFor` returns `(names, cpes, mapped)`, and `nearbyNames` is the one source of nearby-name inputs. `a72bd84`: the 503 detail names no time limit.
- Phase 4 Step 1: `serve` reads a `pg_dump` copy of the ingest database (`cvert_phase4`), not the database itself, because its embedded worker pool would claim the Phase 2 worker's feed jobs and run them with older feed code. Detail at Phase 4 Step 1.
- Phase 4 Step 6: the index write cost is measured on a copy, and the Phase 2 ingest (database, volume, container and the locked `check-ingest` worktree) is kept as lasting data at Sam's request, not removed. Detail at Phase 4 Step 6.
- Phase 4 Step 6, how it ran (2026-11-13): each run restored the copy from one dump, so no run merged data an earlier run had rewritten, and every run read the same fixed 7-day NVD window. The rate is taken from merge time alone (`cve_raw_payloads.ingested_at`), not from the worker log, because NVD fetch time and two HTTP 524 retries would otherwise count. The step ran four times, alternating with and without the indexes, not twice, because the first pair differed by more than the effect later turned out to be. Detail in Phase 4 notes.
- `715df44`, controller's change after its end-to-end check of `2e5a57f`: a CPE item version that is not dotted numbers (`6.8.0-45-generic`) no longer clears its product's floor. No row can be compared with it, so it shares the floored read, and `EvaluateCPERows` answers it `invalid_version` on every advisory with rows, read or left out, whichever row comes first. Before, the first row's reason (`no_version_bounds`, `invalid_range`) could stand in place of `invalid_version`, a reason-only change for such items. A 10-version LTS kernel fleet answers identically with or without such an item. Log `dev/implementation-log/2026-11-10T1200Z-check-non-dotted-version-shares-the-floor.md`.
- **Decided by Sam on 2026-11-10, design change to section 4.2:** NVD bounds that are not dotted numbers (`2.0b10`, `1.0.2zf`) are compared by their leading dotted numbers where those differ (`version.CheckProduct`, `6ef031b`; review fixes `4300c7c`: CPE wildcards, `%` and empty ranges are never compared). Added to PR #218. Effect in Phase 4 notes; log `dev/implementation-log/2026-11-10T1041Z-check-nvd-bounds-by-leading-numbers.md`.
- **Decided by Sam on 2026-11-10, design change to sections 4.2 and 9:** the CPE lookup leaves unread the NVD rows whose ranges lie wholly below the key's floor, and returns one count row per CVE for them (`08b6595`). The floor was first the item version's first two components, one key per floor; the controller's end-to-end run showed that form reading a product once per floor (50 Firefox versions 4.7 s, and HTTP 422 for 500 heavy items and for 300 kernel versions), so the rework (`2e5a57f`) gives each product one key whose floor is the lowest version asked of it (log `dev/implementation-log/2026-11-10T1148Z-check-cpe-lookup-one-read-per-product.md`). The rework also folds in an independent review of `08b6595`: stored rows and count rows share one `LIMIT`, and each advisory's CPE rows are sorted before evaluation so its reason and matched ranges do not depend on the order rows are read in. `CPEKey` gains `Floor`, `CPERow` gains `Below`, `EvaluateCPERows` takes the count, and the version check snapshot sets `jit = off`. Kernel `6.12.0` reads 2,064 rows in place of 82,061 and is answered; no answer changes for an item that was under its limits. The commits are on the implementing agent's branch, for the controller session to merge into the branch of PR #218. Measurements in Phase 4 notes ("Rows below the version"); log `dev/implementation-log/2026-11-10T1129Z-check-cpe-lookup-leaves-rows-below-the-version-unread.md`.

- Phase 2 Step 1: the ingest ran from `dev` at `2c9fac0`, not the Phase 1 merge `45357f5`. `2c9fac0` adds PR #215 (docs) and PR #216, which renamed the GHSA token variable to `GITHUB_GHSA_TOKEN`; the Phase 1 merge reads the old name. The worker was later restarted on `4356557`, `f663fd7` and `f56bde0` to pick up PRs #217, #221 and #222. No build added a migration; the database stayed at version 59.
- Phase 2 Step 3: the env copy differs from the developer's `.env` in two ways besides the port. `DB_QUERY_EXEC_MODE` is `cache_describe`, because `.env` said `simple_protocol` and current code refuses it. `APP_DB_PASSWORD` is generated, because `.env` had none and the compose file requires it.
- Phase 2 completion: the final backup's full restore was tested later than planned. At completion the database was 34 GB and the Docker data disk shared a drive with 23 GB free, so the backup was checked first by reading every data block and restoring the schema alone into a scratch database. Once space was freed, during Phase 4, a full restore into a throwaway database passed on 2026-11-12: the restored row counts match the counts at dump time exactly.
- Phase 4 go/no-go run (2026-11-12): the copy was migrated to version 61 before measuring, because merging `dev` into PR #218 brought migrations 000060 and 000061 (#224, #225), and the CPE statement at `7dae4bf` reads the index 000061 rebuilds. The ingest database itself stays at version 59.
- Phase 4 Step 3, "a current patched version": NVD's highest fix bounds were not the current releases, because the CNAs publish fixes NVD has not yet analysed. Each current version is the lowest on its line for which the endpoint lists nothing Affected, found by moving to the highest same-line `fixed_version` the endpoint reported until none was left.
- Phase 4 Step 4, the go/no-go decision (2026-11-12): Sam asked for two independent reviews of the options (Claude Fable 5.2 and Codex, both at high effort), kept open for discussion, with their consensus to be built. Five rounds and measurements on the copy reached consensus on every point. The design changed (design sections 4.3, 4.5, 4.7, 6, 9, 11, 12 and 15, each marked as amended 2026-11-12), built in `0241f0d` on PR #218: item status `unresolved` and the new reasons `evaluation_failed`, `sdk_version_not_comparable` and `distro_stream_incomplete`; `data_incomplete` also with no advisory; failure flags kept per advisory; `counts.cannot_evaluate_by_reason`; both Ubuntu streams read for a release, with `ecosystem` on package ranges and `fix_ecosystem` on advisories, and Pro sub-streams never cleared; `.NET` SDK numbers not cleared by runtime ranges; `nodejs:nodejs` and `f5:nginx_open_source` in the name table; the .NET Framework, OpenAPI.NET and Ruby's OpenSSL extension as other products; CNA bounds with a letter suffix read by their leading numbers to say a version is outside; check slots from 4 to 1. Not built: loosening `cna_cannot_clear` or clearing on unreadable CNA entries (counterexamples in design section 15), and the `cna_cannot_clear` splits.

### Discoveries

- `packageurl-go` was already in the module graph at v0.1.5 through `osv-scalibr`. Task 1.1 made v0.1.7 a direct dependency, which raises `osv-scalibr`'s copy to v0.1.7 as well. `internal/version` tests pass.
- `package_key` appears in `GET /cves/{id}/sources`, because that endpoint returns each source's `normalized_json`, which is the marshalled `CanonicalPatch` (`internal/api/cves.go` `getCVESourcesHandler`). `GET /cves/{id}` does not return it, as the plan requires.
- **For Sam (display only, no effect on verdicts):** `GET /cves/{id}` (`CNAAffectedResponse` in `internal/api/cves.go`) does not show `package_key`. So a CNA entry kept only for its `packageURL` appears as `{"collection_url": ..., "versions": []}`, with nothing naming the package. Two copies that differ only in `packageURL` appear as two identical entries. CVE 5 does not allow the first shape, so it should be rare. The choice is to add `package_key` to the response, or to accept the empty-looking entry.
- Phase 2 measurement to add: count stored keys that contain whitespace (`package_key ~ '\s'`). `ecosystem.PackageKey("pkg:npm/fastify ")` keeps the trailing space, so such a key never matches a request. A missed match can only produce `no_advisory_found`, never "not affected". The count shows whether trimming on both sides is worth adding.
- `package_key` is computed when a record is parsed, and stored inside `cve_sources.normalized_json`, so a re-merge reuses it. A later change to `ecosystem.FromPurl` or `FoldPackageName` needs a backfill: refetch NVD and MITRE, or re-parse `cve_raw_payloads`. Otherwise old keys hide CNA-only package advisories. `cve_affected_packages` folds at query time and does not have this problem.
- Pitfall DB-19 (`dev/implementation-pitfalls.md`, "CREATE INDEX CONCURRENTLY requires migration framework coordination") says `IF NOT EXISTS` makes a retry succeed. A failed concurrent build leaves an INVALID index of that name, and `IF NOT EXISTS` then skips it without an error. The check lookups would fall back to the slow plans design section 9 measured. A `doctor` check for `pg_index.indisvalid = false` would surface it. This affects every migration, not only 000059.
- **Decided by Sam on 2026-11-09 (affects Phase 3):** design section 3.2 refuses only the `repository_url` qualifier as naming a possibly non-public package. The purl specification also defines `download_url` and `vcs_url`, so `pkg:npm/foo@1?download_url=https://evil/x.tgz` maps to public npm `foo`. A request purl with either qualifier is refused with `unsupported_repository` (Task 3.2), because a private fork answered as the public package could get a wrong "not affected". A stored CNA `packageURL` with either qualifier keeps its key, and `FromPurl` stays as it is: CNA data can only condemn a version, so the worst case is a false Affected, while dropping the key would lose evidence.
- `FromPurl` accepts namespace shapes no registry holds: `pkg:npm/scope/name` (no `@`), a Maven namespace containing `/`, and Composer names with three segments. They name no real package, so a lookup answers `no_advisory_found`, never a wrong "not affected". Phase 3's `ParseItem` could refuse them as `invalid_purl`.
- Task 3.2 (`internal/check/input.go`) choices that the plan and design leave open, each failing safe:
  - A CPE version component of `-` counts as no version stated, like `*`.
  - A `*` or `?` inside a CPE vendor or product (`foo*`) is not refused. It matches no stored row, so the answer is `no_advisory_found`.
  - A purl within 1,024 characters can decode to a version over 256. `internal/version` then answers `invalid_version`.
  - Whitespace is not trimmed in any field.
  - The optional namespace-shape refusal in the entry above was not added.
- **For Sam (Task 3.3, `internal/check/packages.go` `rowCheck`):** a `SEMVER` row in an ecosystem with no comparator (`Root:*`, `GitHub Actions`) is compared as SemVer, because design section 4.1 lists the SEMVER row before the no-comparator row. So such a row can answer Not affected, where an `ECOSYSTEM` row in the same ecosystem answers `unknown_version_scheme`. This follows the OSV schema's definition of `SEMVER`. Phase 4 can count how many such rows exist.
- Task 3.3: OSV also stores `range_type = 'VERSIONS'` (rows built from a `versions` list, with `introduced` = `last_affected`, or no bounds). These rows are compared in the ecosystem's order; a row with no bounds answers `invalid_range`. Range-type matching is exact and upper-case, as merge writes it. A CannotEvaluate advisory takes the reason of its first CannotEvaluate row.
- **For the Phase 3 security review (Task 3.10, `internal/api/check.go`):** the handler takes a check slot before it reads the body, as the plan orders, so a slow upload holds one of the 4 slots for up to the server's 15-second read timeout. Resolved in the phase-end review fixes (see Deviations).
- **For Sam (Phase 3 security review, not changed):** the 4 check slots are per process, with no per-org share. One org within its rate limit can keep all 4 busy with requests built to run near the 30-second limit, for example many CPE items under one large CNA vendor whose nearby-name lookups match nothing, so no row limit applies. Design section 10 chose to count a request once against the org rate limit. A per-org cap of 1 or 2 concurrent checks, or charging the rate limiter per item as `ingest.go` does, would close it. Not measured.
- **For Phase 4 (security review, not changed):** memory per check. Each of 4 slots may hold up to 128 MiB of row strings plus row structs and the encoded response, in a 1 GiB container shared with the worker. Identical items share one read but are serialised once each. Measure on the full corpus.
- Phase 3 security review: the `CheckItem` length limits are stated in descriptions, not `maxLength` tags, because an over-long field answers that item `value_too_long` with a 200, which a `maxLength` would describe as a 422.
- **For Phase 4 (round 2 review, not changed):** Ubuntu's OSV data may put a CVE's package row only under `Ubuntu:Pro:<release>:LTS` for releases past standard support, and a standard-stream item (`Ubuntu:<release>:LTS`) does not read Pro rows. An item whose other advisories are fixed would then answer `not_affected`. Count `UBUNTU-CVE-*` records with a Pro row and no standard row on the ingested corpus.
- **For Phase 4 (round 2 review, not changed):** CPE `part` is never aliased. NVD has used both `a:` and `o:` for some products (`google:android`), so a CVE analysed under the other part, with no matching CNA name, is invisible. Count products with rows under both parts.
- Round 2 review: package names are folded with Go `strings.ToLower` on the request side and SQL `lower()` on the stored side. They differ outside ASCII (U+0130), and a mismatch loses every row for that spelling, so the answer is `no_advisory_found`, not a clearance. Not changed.
- Round 4 review: underscore spellings are mixed between vendor and product but not within one value, so `foo_bar_baz` does not read a CNA product `foo bar_baz`. Design section 4.5 accepts this ("a product name without the fragment"); full coverage needs 2^n spellings. Not changed.
- Phase 3 plan check: a nearby-name row is lifted only by an NVD row with the item's own CPE part (`cpe:2.3:<part>:<vendor>:`), so an `o:microsoft:windows` row does not lift a block for `a:microsoft:.net`. Design section 4.5 says "the CPE's own vendor". The difference gives more `cna_name_uncertain` answers, never a clearance.
- **For Sam (Task 3.11, display only, no effect on verdicts):** an advisory known only from OSV, which includes every distro record, answers `severity` and `cvss_v3_score` as null. `internal/merge/resolve.go` takes a CVSS vector only from a source that also gives a score, OSV gives vectors only, and the OSV adapter sets no severity. Design section 6 says those fields "stay those of the distro's own record". The fix belongs in merge or the OSV adapter, not in the endpoint.
- Task 3.11: the real CVE-2024-7347 CNA entry is `{1.5.13, lessThan *, affected, semver}` with changes at 1.26.2 and 1.27.1, not the `{1.25.0, lessThan 1.27.1}` in the plan's Task 3.5 table and `cnaNginx7347` in `internal/check/cna_test.go`. The verdict for 1.27.0 is the same. With the whole record and no NVD rows, the F5 / NGINX Plus entry makes the advisory `cna_name_uncertain` rather than the design's `cna_indeterminate`; both are cannot evaluate.
- `TestCheckPackageIndexMatchesFoldedName` pins only the package index. Phase 3 should add the same pin tests for the CPE expression (`left(cpe_normalized, 512) COLLATE "C"`, defined in migration 000061) and the CNA expressions (`left(lower(vendor), 256) COLLATE "C"`, and the same for `product`) when `internal/store/check.go` builds those predicates.
- **For Sam (Phase 4 provisional run):** old NVD rows whose exact version or bound is not dotted numbers (`php:2.0b10`, OpenSSL `1.0.2zf`) answer `invalid_range`, which holds Node, PHP, OpenSSL and PostgreSQL items at `cannot_evaluate` at every version, patched or not. A leading-number comparison rule would settle all but one of them as Not affected. Numbers in Phase 4 notes. Sam chose the rule on 2026-11-10; see Deviations.
- **For Sam (Phase 4 provisional run):** `o:linux:linux_kernel` has 82,061 vulnerable rows before NVD finishes, over the 50,000 per-key limit, so every Linux kernel item answers `too_many_candidates`. A publication-date cutoff would drop old unbounded rows and can give a wrong "not affected"; a version-aware lookup filter would not (Phase 4 notes).
- **Phase 4 provisional run, performance:** evaluation re-parses every bound per comparison (`internal/version` `CheckNumeric`, `validateRange`, `math/big`) and re-splits each CPE per item (`internal/check` `splitCPE`). 500 CPE items over the largest products took 14 to 18 s and allocated 11.4 GiB on the partial corpus. Re-measured on the complete corpus before a fix is proposed. Numbers in Phase 4 notes.
- PostgreSQL JIT (found while measuring the CPE lookup, 2026-11-10): the planner cannot see how many rows a key holds, so a version check statement's estimated cost passes the default JIT thresholds once a request has a few keys. On the CPE statement JIT cost 30 to 70 ms for one key and 0.96 to 1.24 s for four or five, and saved nothing. `withOrgSnapshotTx` (`internal/store/store.go`) now runs `SET LOCAL jit = off`. The packages and CNA statements were not measured with and without it.
- **For Sam (assessed 2026-11-10, not built):** the row filter of the CPE lookup does not carry over to package rows or CNA rows. Detail and measurements in Phase 4 notes ("Rows below the version", last two items).
- Found by the end-to-end run of 300 kernel items (2026-11-10, not changed, present before the rule): `evaluateItem` (`internal/check/evaluate.go`) groups every row of an item's keys in `rowsOf` before it looks at the keys' overflow flags, so each item of a key over its limit allocates for 50,000 rows and then answers `too_many_candidates`: 5.1 GiB for the 300 items. Checking the flags first would avoid it. Fixed in `bfe4426` at Sam's request (`overItemLimit` runs before `rowsOf`): the 300 items now allocate 51 MiB in 0.29 s, down from 5.35 GiB in 2.3 s, with identical responses. Log `dev/implementation-log/2026-11-10T2049Z-check-refuse-over-limit-items-before-grouping.md`.
- **Decided by Sam on 2026-11-12 (affects Phase 3):** a CPE or package name over the btree row limit failed the merge of its CVE. Migration 000061 (bounded CPE and package keys) rebuilt `cve_cpe_matches_check_idx` on `left(cpe_normalized, 512) COLLATE "C"`. CPEs stay stored in full, because watchlists and this endpoint match them by prefix. Task 3.9's CPE statement, `CPEKey` and its tests, and design section 9 were updated to match. The merge leaves out package names over 1,024 bytes (`maxIndexedPackageNameBytes` in `internal/merge/pipeline.go`), so `cve_affected_packages_check_idx` is unchanged. The migration also dropped `cve_affected_packages_eco_pkg_idx`, which no query could use, so Phase 4 no longer measures it.

- **Feed client body cap (fixed, PR #217):** the shared feed HTTP client capped bodies at 512 MiB and cut off larger ones without an error, so MITRE's and OSV's archives were truncated and ingested partly. It now fails loudly. See `dev/implementation-log/2026-11-10T0600Z-feed-body-cap-fails-loudly.md`.
- **Decode loop (fixed, PR #221):** an NVD page body that ended early made the NVD, GHSA and KEV parsers log and skip the same sticky `json.Decoder` error forever. The ingest made no progress for 11 hours. A record is now skipped only on `*json.UnmarshalTypeError`; any other error fails the page. Pitfall FEED-1 and `dev/implementation-log/2026-11-11T0453Z-feed-decode-errors-fail-the-page.md`.
- **MSRC never finished a first sync (fixed, PR #222):** the adapter downloaded all 10,146 CSAF files in `changes.csv` in one page, more than a 10-minute job can do at one request per second, and every failure discarded the whole batch. It now pages 100 files at a time with a (timestamp, path) cursor, and finished all 10,146 files. Pitfall FEED-19 and `dev/implementation-log/2026-11-11T1447Z-msrc-pages-csaf-downloads.md`.
- **Long index keys (fixed, PRs #224 and #225):** a reference URL, CPE or package name over the btree row limit failed the merge of its CVE. Red Hat sends a reference URL over 3,000 bytes for CVE-2006-4339, so 11 of 89 Red Hat jobs failed during the ingest; Red Hat is not a completion signal. The kept ingest database needs a worker build with migrations 000060 and 000061 before Red Hat stops failing there.
- **For Sam, NVD syntax errors (not changed):** on a `*json.SyntaxError` the NVD parser returns the records read so far as a success, and the cursor still advances by 2,000, so the rest of that page is lost silently. Failing the page instead would make a page that is always corrupt retry forever. `internal/feed/nvd/adapter.go` `parseNVDResponse`.
- **For Sam, NVD body limit (not changed):** NVD reads each page through `io.LimitReader` at 50 MB, which ends a larger page without an error of its own. Since PR #221 such a page fails instead of looping, but it would fail on every retry. Measured pages are 6 to 10 MB.
- **For Sam, MSRC rate limit (not changed):** MSRC answers HTTP 429 after anywhere from 10 to a few hundred requests at one per second, and a job that saved pages and then got a 429 still counts as a failure, so its backoff grows. The first sync finished anyway; a slower rate or treating a 429 after saved pages as a partial run would make it steadier.
- **For Sam, OSV archive reuse (not changed):** every OSV backfill job downloads the whole 2.9 GB `all.zip` again. The backfill took 135 OSV jobs, about 390 GB of downloads. Keeping the first job's archive for the length of the backfill (keyed by the cursor's `snapshot`) would save that at the cost of 2.9 GB of disk held during the backfill.
- `cve_affected_packages_eco_pkg_idx`: no application query used it (5 scans since the stats were last reset, a period with no API traffic). Migration 000061 (#225) dropped it.
- **Ingest pace on this host:** 49 hours end to end, of which 11 were the decode-loop stall. OSV was last, at about 70,000 advisories an hour once the other feeds had caught up, and about ten times slower on its last `UBUNTU-CVE-*` records, whose merge rebuilds CVEs that many feeds already describe. `feed_ingest` runs one job at a time and the feeds take turns.
- **For Sam (go/no-go run, wrong "not affected"; fixed in `0241f0d`):** 27,145 `UBUNTU-CVE-*` records have rows only under a plain `Ubuntu:Pro:<release>` stream, with no standard-stream row for the same package: 16,337 for 20.04, 17,352 for 18.04, 18,100 for 16.04, 14,444 for 14.04, 5,077 for 22.04, 4,028 for 24.04 and 1,636 for 26.04 (a record can count under several releases). An earlier total of 34,326 also counted the FIPS and Realtime sub-streams, which have no standard counterpart by construction. A standard-stream item (`Ubuntu:<release>:LTS`) read no Pro rows, so for these records it read no advisory at all and could answer `not_affected` where Ubuntu reports the package affected. The reverse also held: of 2,687,259 standard rows on releases with a Pro stream, 70 have a Pro row for the same record and package, so a Pro item missed every standard USN (USN-8847-1 for `openssl` under `Ubuntu:Pro:22.04:LTS`). This is the round 2 review's Pro-row note, now counted. The rows are as OSV publishes them: OSV's own record for UBUNTU-CVE-2007-4774 lists four kernel packages, all under `Ubuntu:Pro:14.04:LTS`, and UBUNTU-CVE-2005-10004 lists Pro 14.04 to 20.04 only. So the decision belongs to the check endpoint: whether a standard-stream item may read Pro rows. All 65,453 OSV `UBUNTU-CVE-*` records are stored under their own IDs.
- **For Sam (go/no-go run):** Microsoft's CNA states both runtime versions (`10.0.15`) and SDK versions (`10.0.403`) under one product, `.NET 10.0`. NVD's `microsoft:.net` and `.net_core` rows state runtime versions only: no vulnerable row on any line has a bound with a third component of 100 or more, so runtime ranges would clear an SDK version (fixed in `0241f0d`: `sdk_version_not_comparable`). A runtime version is inside the SDK ranges by number, so `.NET` `10.0.15` (the current runtime) answers Affected from SDK ranges, and an advisory with both kinds of range reports no `fixed_version`.
- **For Sam (go/no-go run):** with NVD complete, the CPE lookup's row filter no longer brings the LTS kernels under the 50,000-row limit: `o:linux:linux_kernel` has 165,349 vulnerable rows, and `5.15.170`, `6.1.140` and `6.6.95` each answer `too_many_candidates`; `6.12.50` and later are answered. Every kernel version also carries 73 `no_version_bounds` advisories, so no kernel item answers `not_affected`.
- **For Sam (go/no-go run, memory):** 500 items over the largest CPE products took 8.1 to 8.3 s and allocated 3.97 GiB, with 605 to 687 MiB resident afterwards (2.0 s and 1.2 GiB on the partial ingest). Four such requests at once, one per check slot, would not fit the 1 GiB container that also runs the worker.
- **Go/no-go run, missing CPE spellings (fixed in `0241f0d`):** NVD files recent nginx CVEs under `f5:nginx_open_source` (45 vulnerable rows, 26 CVEs) and Node 0.6 to 0.10 under `nodejs:nodejs` (3 CVEs); the name table had neither. 25 of the 27 nginx advisories that answered `cna_cannot_clear` at `1.31.7` had NVD rows there, and older nginx versions missed Affected advisories (`1.29.3`: 18 Affected before, 20 after).
- **Go/no-go run, Ubuntu Pro sub-streams:** `FIPS`, `FIPS-updates`, `FIPS-preview` and `Realtime` list only some of their release's advisories for their own packages: `Ubuntu:Pro:FIPS-updates:22.04:LTS` lists `openssl` but not USN-8847-1, USN-8678-1 or USN-8625-1, and the Realtime streams miss 19,444 and 14,714 of the plain streams' (record, package) pairs. A sub-stream item now never answers `not_affected` (`distro_stream_incomplete`).
- **Go/no-go run, what the 48 `cna_name_uncertain` advisories were:** the .NET Framework (16 CVEs), ASP.NET Core (8), OpenAPI.NET (2), the `Microsoft.NetCore.App.Runtime.*` and `Microsoft.AspNetCore.App.Runtime.*` packages (2), PTC's `.NET-SDK` filed under Microsoft (2), NGINX Plus beside NGINX Open Source (6), NGINX JavaScript, Ingress Controller and Gateway Fabric (11), and Ruby's OpenSSL extension (1). The Visual Studio entries listed beside them never matched the fragment `.net`.
- **Go/no-go run, what the 117 `cna_cannot_clear` advisories were:** each had a CNA name row whose entries stated versions that exclude the current release (OpenSSL CVE-2026-88822 is `[4.0.0, 4.0.4)` at `4.0.4`); 84 had no NVD CPE row at all. For these products `unresolved` is the steady answer until NVD analyses the CVE.

- **PR review before merge (2026-11-12, Fable 5.2):** fixed in this PR: a CPE item's update component (`22.0.0:rc1`) was ignored, so a pre-release was compared as the release and could be cleared; a CPE vendor or product with an unescaped character such as `notepad++` matched no row and read as nothing known (now `invalid_cpe`). Recorded, not changed: the response is encoded after the check slot is released and held for up to 30 seconds while written, so write-phase memory belongs to the release gate on peak memory (design section 9); one slot lets one org keep the endpoint at 503 for others within its rate limit (per-org fairness, already a release matter); PostgreSQL parameter logging would record items (design section 10).
- **For Sam (PR review): distros whose feeds list fixes only.** On the complete ingest, Red Hat (636,727 rows), AlmaLinux, Rocky Linux, Alpine (108,574), SUSE and openSUSE store no unfixed row, so a CVE the distribution has not fixed has no row, and an item with every published fix applied answers `not_affected` while the distribution reports it affected. Debian, Ubuntu and Wolfi store unfixed rows. The status description now says what `not_affected` means for those six (design section 6). Whether their items should answer `not_affected` at all is a decision for Sam.
---

## Rules for every task

**Project rules (`CLAUDE.md`).** Every code file starts with two `// ABOUTME: ` lines. Comments describe what the code does and never what it used to do. No names containing "new", "legacy", "old", "improved" or "unified". Never remove a comment unless it is false. Never skip a pre-commit hook. Never use `git add -A` without a `git status` first. Address the project owner as Sam.

**No backward compatibility.** Sam has decided there are no existing installs. Do not add data migrations, cursor resets or re-canonicalisation.

**The failure to design against is a wrong "not affected".** When a rule seems not to cover an input, the answer is `cannot_evaluate`, and you record the gap under Discoveries. Never resolve it towards "not affected".

**Fresh worktrees.** `web/embed.go` embeds `web/dist`, so packages that reach it (including `./internal/api`, `go build ./...` and the linter) do not compile until the frontend is built. Before the first such command in a new worktree, run `cd web && npm ci && npm run build-only`.

**Testing.** Docker is required for database tests, and it is shared with other sessions: run targeted tests while working. If every database test fails at setup with `reaper: new reaper: ... "removing"`, rerun with `TESTCONTAINERS_RYUK_DISABLED=true`; that failure is about Docker, not the code. Go commands in a worktree use `go -C <worktree>` or run from the worktree.

**Regenerating sqlc on this host.** `sqlc generate` writes LF and the checkout is CRLF, so every generated file shows as modified. After generating, list the files with real changes using `git diff --ignore-cr-at-eol --stat -- internal/store/generated`, restore all the others with one `git restore -- internal/store/generated ':!internal/store/generated/<changed>.go'` command naming each real change, and confirm with `git status --short`.

**Before starting each task:**
1. Invoke /superpowers:test-driven-development.
2. Read `dev/testing-pitfalls.md`.
Follow TDD: write a failing test, implement, verify green.

**Before marking each task complete:**
1. Review the tests against `dev/testing-pitfalls.md`.
2. Verify coverage of error paths and edge cases.
3. Run the tests and confirm green.

**After each task's commit.** Add one file to `dev/implementation-log/` per its `README.md`, and commit it.

**End of each phase with code (1 and 3).** Review the batch from multiple perspectives, in at least 3 rounds, and keep going if round 3 still finds issues. Then run `golangci-lint run` and `go test ./... -count=1 -timeout=600s 2>&1 | tee test-run.log`, and open a pull request to `dev` with `gh pr create --base dev`.

**Deliberately not done.** No item-level "lowest version that clears everything", no `packageName` or `collectionURL` lookups, no scopes (AUTH-3), no per-key rate limits (AUTH-7), no version condition in alert rules. If you find yourself building one, stop.

---

## Phase 1 — Data changes

**Execution Status:** ✅ SHIPPED 2026-11-10. [PR #213](https://github.com/scarson/CVErt-Ops/pull/213) merged to `dev` as `45357f5`, from branch `claude/check-data-72f424`. The four tasks are `2018ce4`, `c79cd32`, `80c273b` and `356bf6e`, with review fixes up to `b741212`. `golangci-lint` was clean and `go test ./...` passed at `b741212`. Commits after it change only docs. CI runs only for `main`, so the PR to `dev` had no checks.

Branch `feat/check-data` from `dev`. (Deviation: the executing session's worktree branch is `claude/check-data-72f424`, cut from `dev` at eb69a13; it was not renamed.) These four tasks change what ingest writes, so a walk under earlier code would have to be repeated. Tasks run in order.

### Task 1.1: Map purls to ecosystems

**Files:**
- Create: `internal/ecosystem/purl.go`, `internal/ecosystem/purl_test.go`
- Modify: `internal/ecosystem/ecosystem.go`, `go.mod`, `go.sum`

**Evidence and behaviour.** Requests (design section 3.2) and stored CNA `packageURL` values (design section 4.6) must map through one function, or a CNA row and a request can name one package differently. `github.com/package-url/packageurl-go` v0.1.7 passed `dependency-check` on 2026-11-08 (design section 14). `Valid` at `ecosystem.go:61` accepts a bare `Debian`.

**Step 1: Write the failing tests.** `purl_test.go` is table-driven on `FromPurl`, with one row for each row of the three tables in design section 3.2 plus:

| Input | Expected |
|---|---|
| `pkg:npm/%40scope/name@1.0.0` | `npm`, `@scope/name`, `1.0.0` |
| `pkg:golang/stdlib@1.26.0` | `Go`, `stdlib`, `1.26.0` |
| `pkg:golang/github.com/foo/bar@v1.2.3` | `Go`, `github.com/foo/bar`, `v1.2.3` |
| `pkg:maven/org.apache/log4j@2.14.0` | `Maven`, `org.apache:log4j`, `2.14.0` |
| `pkg:composer/symfony/http@6.0` | `Packagist`, `symfony/http`, `6.0` |
| `pkg:composer/http@6.0`, `pkg:maven/log4j@1` | code `invalid_purl` |
| `pkg:hex/acme/foo@2.3.0`, `pkg:cargo/x/y@1` | code `unsupported_purl_namespace` |
| `pkg:npm/foo@1?repository_url=https://r.example` | code `unsupported_repository` |
| `pkg:npm/foo@1#sub` | code `invalid_purl` |
| `pkg:rpm/redhat/foo@1` | code `unsupported_purl_type` |
| `pkg:deb/ubuntu/php8.5@8.5.4-0ubuntu1.4?distro=ubuntu-26.04` | `Ubuntu:26.04:LTS`, `php8.5`, `8.5.4-0ubuntu1.4` |
| same with `distro=ubuntu-25.10` | `Ubuntu:25.10` |
| `pkg:deb/debian/curl@8.0?distro=debian-13.1` | `Debian:13` |
| `pkg:deb/debian/curl@8.0?distro=trixie` | `Debian:13` |
| `pkg:deb/debian/curl@8.0` | code `distro_required` |
| `pkg:deb/ubuntu/x@1?distro=esm-infra/focal` | code `distro_not_recognised` |
| `pkg:deb/ubuntu/x@1?distro=debian-13`, `pkg:deb/debian/x@1?distro=noble`, `pkg:deb/debian/x@1?distro=alpine-3.20`, `pkg:apk/alpine/x@1?distro=ubuntu-26.04`, `pkg:apk/alpine/x@1?distro=noble` | code `conflicting_distro` |
| `pkg:deb/debian/foo@1.0?distro=debian-13&epoch=2` | version `2:1.0` |
| `pkg:deb/debian/foo@2:1.0?distro=debian-13&epoch=2` | version `2:1.0` |
| `pkg:deb/debian/foo@2:1.0?distro=debian-13&epoch=1` | code `conflicting_version` |
| `pkg:deb/debian/foo@1?distro=debian-13&epoch=x` | code `invalid_purl` |
| `pkg:apk/alpine/musl@1.2.4-r0?distro=3.20.3` | `Alpine:v3.20` |
| `pkg:apk/alpine/musl@1.2.4-r0?distro=alpine-3.20` | `Alpine:v3.20` |
| `pkg:npm/fastify` | `npm`, `fastify`, empty version, no error |
| `pkg:npm/foo%00bar@1`, `pkg:deb/debian/foo%00@1?distro=debian-13` | code `invalid_purl` |

And `TestPackageKey`: `pkg:npm/fastify` gives `npm/fastify`; `pkg:pypi/friendly--bard` and `pkg:pypi/Friendly_Bard` both give `PyPI/friendly-bard`; a purl with `repository_url`, a private `hex` namespace, a `deb` purl with a valid `distro`, malformed input, and an `npm` name of 8,000 bytes all give `""`. `TestPackageKeyFor`: `("PyPI", "friendly.bard")` gives `PyPI/friendly-bard`. `TestIsDistro`: `Debian:13`, `Ubuntu:26.04:LTS`, `Wolfi`, `Red Hat:x` true; `npm`, `Packagist:x`, `Root:x` false. `TestNeedsRelease`: `Debian`, `Ubuntu` true; `Debian:13`, `Wolfi`, `npm`, `Packagist` false.

**Step 2: Run.** `go test ./internal/ecosystem/ -count=1`. Expected: FAIL, undefined `FromPurl`.

**Step 3: Add the dependency.** `go get github.com/package-url/packageurl-go@v0.1.7`.

**Step 4: Implement `internal/ecosystem/purl.go`.**

```go
// ABOUTME: Maps package URLs to canonical ecosystems, package names and versions.
// ABOUTME: Requests and stored CNA package identities share this mapping, so one package has one identity.
package ecosystem

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"

	packageurl "github.com/package-url/packageurl-go"
)

// PurlError carries a stable code that the check endpoint returns as error.code.
type PurlError struct {
	Code string
}

func (e *PurlError) Error() string { return "purl: " + e.Code }

func purlError(code string) error { return &PurlError{Code: code} }

// PurlComponent is what a package URL identifies. Version is empty when the
// purl has none, as stored CNA package URLs do not.
type PurlComponent struct {
	Ecosystem string
	Name      string
	Version   string
}

var purlEcosystems = map[string]string{
	"npm": "npm", "pypi": "PyPI", "golang": "Go", "maven": "Maven", "cargo": "crates.io",
	"gem": "RubyGems", "nuget": "NuGet", "hex": "Hex", "pub": "Pub", "composer": "Packagist",
}

// distroCodenames holds releases that OSV's purls and the purl specification name
// by codename. An unlisted codename is refused, never guessed.
var distroCodenames = map[string]struct{ family, ecosystem string }{
	"bullseye": {"debian", "Debian:11"},
	"bookworm": {"debian", "Debian:12"},
	"trixie":   {"debian", "Debian:13"},
	"jammy":    {"ubuntu", "Ubuntu:22.04:LTS"},
	"noble":    {"ubuntu", "Ubuntu:24.04:LTS"},
	"plucky":   {"ubuntu", "Ubuntu:25.04"},
	"questing": {"ubuntu", "Ubuntu:25.10"},
	"resolute": {"ubuntu", "Ubuntu:26.04:LTS"},
}

var (
	debDistro    = regexp.MustCompile(`^(ubuntu|debian)-([0-9]+)(?:\.([0-9]+))?$`)
	alpineDistro = regexp.MustCompile(`^(?:alpine-)?([0-9]+)\.([0-9]+)(?:\.[0-9]+)?$`)
	allDigits    = regexp.MustCompile(`^[0-9]+$`)
	leadingEpoch = regexp.MustCompile(`^([0-9]+):`)
)

// FromPurl resolves a package URL. A purl that could name a package the public
// registry does not hold is refused rather than mapped to the public name.
func FromPurl(raw string) (PurlComponent, error) {
	p, err := packageurl.FromString(raw)
	if err != nil || p.Subpath != "" {
		return PurlComponent{}, purlError("invalid_purl")
	}
	qualifiers := p.Qualifiers.Map()
	if _, ok := qualifiers["repository_url"]; ok {
		return PurlComponent{}, purlError("unsupported_repository")
	}

	switch p.Type {
	case "deb":
		eco, err := debEcosystem(p.Namespace, qualifiers["distro"])
		if err != nil {
			return PurlComponent{}, err
		}
		version, err := applyEpoch(p.Version, qualifiers["epoch"])
		if err != nil {
			return PurlComponent{}, err
		}
		return validated(PurlComponent{Ecosystem: eco, Name: p.Name, Version: version})
	case "apk":
		eco, err := alpineEcosystem(p.Namespace, qualifiers["distro"])
		if err != nil {
			return PurlComponent{}, err
		}
		return validated(PurlComponent{Ecosystem: eco, Name: p.Name, Version: p.Version})
	}

	eco, ok := purlEcosystems[p.Type]
	if !ok {
		return PurlComponent{}, purlError("unsupported_purl_type")
	}
	name, err := joinPurlName(p.Type, p.Namespace, p.Name)
	if err != nil {
		return PurlComponent{}, err
	}
	return validated(PurlComponent{Ecosystem: eco, Name: name, Version: p.Version})
}

// validated refuses control characters, which percent-decoding can produce. PostgreSQL
// rejects NUL in text and in jsonb, so a stored one would fail the whole CVE's merge.
func validated(c PurlComponent) (PurlComponent, error) {
	if strings.ContainsFunc(c.Name+c.Version, unicode.IsControl) {
		return PurlComponent{}, purlError("invalid_purl")
	}
	return c, nil
}

func joinPurlName(purlType, namespace, name string) (string, error) {
	switch purlType {
	case "npm", "golang":
		if namespace == "" {
			return name, nil
		}
		return namespace + "/" + name, nil
	case "maven":
		if namespace == "" {
			return "", purlError("invalid_purl")
		}
		return namespace + ":" + name, nil
	case "composer":
		if namespace == "" {
			return "", purlError("invalid_purl")
		}
		return namespace + "/" + name, nil
	}
	if namespace != "" {
		return "", purlError("unsupported_purl_namespace")
	}
	return name, nil
}

func debEcosystem(namespace, distro string) (string, error) {
	if namespace != "debian" && namespace != "ubuntu" {
		return "", purlError("unsupported_purl_namespace")
	}
	if distro == "" {
		return "", purlError("distro_required")
	}
	if named, ok := distroCodenames[distro]; ok {
		if named.family != namespace {
			return "", purlError("conflicting_distro")
		}
		return named.ecosystem, nil
	}
	if strings.HasPrefix(distro, "alpine-") {
		return "", purlError("conflicting_distro")
	}
	m := debDistro.FindStringSubmatch(distro)
	if m == nil {
		return "", purlError("distro_not_recognised")
	}
	family, major, minor := m[1], m[2], m[3]
	if family != namespace {
		return "", purlError("conflicting_distro")
	}
	if family == "debian" {
		return "Debian:" + major, nil
	}
	if minor == "" {
		return "", purlError("distro_not_recognised")
	}
	eco := "Ubuntu:" + major + "." + minor
	if year, err := strconv.Atoi(major); err == nil && year%2 == 0 && minor == "04" {
		eco += ":LTS"
	}
	return eco, nil
}

func alpineEcosystem(namespace, distro string) (string, error) {
	if namespace != "alpine" {
		return "", purlError("unsupported_purl_namespace")
	}
	if distro == "" {
		return "", purlError("distro_required")
	}
	if _, named := distroCodenames[distro]; named || debDistro.MatchString(distro) {
		return "", purlError("conflicting_distro")
	}
	m := alpineDistro.FindStringSubmatch(distro)
	if m == nil {
		return "", purlError("distro_not_recognised")
	}
	return "Alpine:v" + m[1] + "." + m[2], nil
}

func applyEpoch(version, epoch string) (string, error) {
	if epoch == "" {
		return version, nil
	}
	if !allDigits.MatchString(epoch) {
		return "", purlError("invalid_purl")
	}
	if m := leadingEpoch.FindStringSubmatch(version); m != nil {
		if strings.TrimLeft(m[1], "0") != strings.TrimLeft(epoch, "0") {
			return "", purlError("conflicting_version")
		}
		return version, nil
	}
	if version == "" {
		return "", nil
	}
	return epoch + ":" + version, nil
}

// maxPackageKeyBytes keeps a stored key under the btree row limit. Upstream URLs
// have no length bound, and a key over the limit would fail the merge of the whole
// CVE. Any key a request can form is shorter: 64 characters of ecosystem and 512
// of name.
const maxPackageKeyBytes = 2600

// PackageKey returns the stored identity of a CNA package URL, or "" when the URL
// is refused, is too long to index, or names a distro package, whose CNA data
// describes upstream.
func PackageKey(raw string) string {
	c, err := FromPurl(raw)
	if err != nil || IsDistro(c.Ecosystem) {
		return ""
	}
	key := PackageKeyFor(c.Ecosystem, c.Name)
	if len(key) > maxPackageKeyBytes {
		return ""
	}
	return key
}

// PackageKeyFor returns the identity a package item looks up.
func PackageKeyFor(ecosystem, name string) string {
	return ecosystem + "/" + FoldPackageName(ecosystem, name)
}
```

Add to `ecosystem.go`:

```go
// distros holds the base names whose packages are built by a distribution, where
// one version string has meaning only within one release.
var distros = map[string]bool{
	"AlmaLinux": true, "Alpaquita": true, "Alpine": true, "Azure Linux": true,
	"BellSoft Hardened Containers": true, "Chainguard": true, "Debian": true, "Echo": true,
	"Mageia": true, "MinimOS": true, "Red Hat": true, "Red Hat Lightwell": true,
	"Rocky Linux": true, "SUSE": true, "TuxCare": true, "Ubuntu": true, "Wolfi": true,
	"openEuler": true, "openSUSE": true,
}

// IsDistro reports whether value names a distribution's packages.
func IsDistro(value string) bool {
	base, _, _ := strings.Cut(value, ":")
	return distros[base]
}

// NeedsRelease reports whether value is a distribution that takes a release and
// names none, so one exact version has no single meaning.
func NeedsRelease(value string) bool {
	return distros[value] && takesSuffix[value]
}
```

**Step 5: Run.** `go test ./internal/ecosystem/ -count=1`. Expected: PASS. If `packageurl-go` keeps `%40scope` encoded or rejects a table row, fix the mapping, not the test, and record what the library did under Discoveries.

**Step 6: Commit.** `git add internal/ecosystem go.mod go.sum` then `git commit -m "feat(ecosystem): map package URLs to canonical ecosystems"`.

> **Deviation (executed 2026-11-10):** the Phase 1 review made `FromPurl` refuse more than the code above, in each case in the safe direction:
> - `validated` also refuses invalid UTF-8 and U+FFFD. PostgreSQL rejects invalid UTF-8, so one such request item would fail a whole request. `packageurl-go` lower-cases `deb`, `apk`, `golang` and `composer` names, which turns invalid bytes into U+FFFD.
> - `debDistro` refuses a major release number with leading zeros, and `alpineDistro` refuses leading zeros in any of its numbers. A Debian point release is dropped, so its form is not checked. `debEcosystem` requires a two-digit Ubuntu month.
>
> Commit ac5ad2b.

### Task 1.2: Store each CNA entry's package identity, and add the lookup indexes

**Files:**
- Create: `migrations/<next>_check_lookups.up.sql`, `migrations/<next>_check_lookups.down.sql`
- Modify: `internal/feed/cna.go:11-18,61-68`, `internal/feed/interface.go:149-156`, `internal/store/queries/cves.sql:134`, `internal/merge/pipeline.go:332-339`, `internal/store/generated/*`
- Test: `internal/feed/cna_test.go`, `internal/merge/version_ranges_integration_test.go`, `internal/store/check_index_test.go`

**Evidence and behaviour.** `cve5AffectedEntry` drops `packageURL`. CVE-2026-107832 in the golden NVD page carries `pkg:npm/fastify`, and no other feed in the golden data has that package. Design sections 4.6 and 9.

Invoke the `schema-review` skill on the migration before writing it. `<next>` is the next free number on `dev` (`000059` when this plan was written); check `migrations/` first, as other work adds migrations. Pitfall DB-16 in `dev/implementation-pitfalls.md`: the migration driver splits on every semicolon, including inside comments, so no comment in either file may contain one.

**Step 1: Write the failing tests.**
- `cna_test.go`: `ParseCNAAffected` on an entry with `"packageURL":"pkg:npm/fastify"` gives `PackageKey: "npm/fastify"`. An entry with `pkg:npm/foo?repository_url=https://r.example` gives `""`. An entry with no `packageURL` gives `""`. An entry whose `packageURL` contains a NUL gives `""`.
- `version_ranges_integration_test.go`: ingesting that patch stores `package_key = 'npm/fastify'` in `cve_cna_affected`, and `material_hash` matches a merge of the same patch without the field.
- `check_index_test.go`: `TestCheckPackageIndexMatchesFoldedName` reads the up migration from `migrations.FS` (`migrations/embed.go`), and asserts that it contains `ecosystem.FoldedNameSQL("ecosystem", "package_name")` verbatim. The design's guarantee that the query and the index cannot drift depends on this.

**Step 2: Run.** Targeted: `go test ./internal/feed/ ./internal/merge/ ./internal/store/ -run 'CNA|PackageKey|CheckPackageIndex' -count=1`. Expected: FAIL.

**Step 3: Write the migration.**

```sql
-- migrate:no-transaction

-- The version check endpoint finds rows by exact package, by CPE prefix and by CNA
-- name. package_key is the CNA packageURL mapped to the identity a package request
-- uses, and is NULL when the entry has none or the URL is refused.
ALTER TABLE cve_cna_affected ADD COLUMN IF NOT EXISTS package_key text;

-- Matches ecosystem.FoldedNameSQL, which builds the query's expression.
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_packages_check_idx
    ON cve_affected_packages (ecosystem,
        (CASE WHEN ecosystem = 'PyPI' THEN regexp_replace(lower(package_name), '[-_.]+', '-', 'g') ELSE lower(package_name) END));

-- C collation so a range on the CPE prefix can use the index whatever the database collation.
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cpe_matches_check_idx
    ON cve_cpe_matches ((cpe_normalized COLLATE "C"));

-- left(..., 256): vendor and product can reach 2,048 characters, and a value over the
-- btree row limit would fail the merge of the whole CVE.
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cna_affected_check_idx
    ON cve_cna_affected ((left(lower(vendor), 256) COLLATE "C"), (left(lower(product), 256) COLLATE "C"));

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cna_affected_package_key_idx
    ON cve_cna_affected (package_key) WHERE package_key IS NOT NULL;
```

Down file, with `-- migrate:no-transaction` as its first line: `DROP INDEX CONCURRENTLY IF EXISTS` for each of the four, then `ALTER TABLE cve_cna_affected DROP COLUMN IF EXISTS package_key;`.

**Step 4: Implement.** Add `PackageURL string `json:"packageURL"`` to `cve5AffectedEntry`. Add `PackageKey string `json:"package_key,omitempty"`` to `CNAAffected`, and document that it is `ecosystem.PackageKey` of the CNA's `packageURL`. Set `PackageKey: ecosystem.PackageKey(e.PackageURL)` in `ParseCNAAffected`. Do not clean the URL first: removing a NUL could turn a refused URL into another package's valid identity, and `FromPurl` refuses control characters itself. Add `package_key` to `InsertCNAAffected` in `cves.sql`, run `sqlc generate` under the rule above, and pass `PackageKey: dbutil.NullString(a.PackageKey)` at `pipeline.go:332`. Do not add `PackageKey` to `MaterialFields`. `GET /cves/{id}` does not gain the field.

**Step 5: Run.** The Step 2 command. Expected: PASS.

**Step 6: Commit.** `git add` the listed files, then `git commit -m "feat(merge): store each CNA entry's package identity and add check lookup indexes"`.

> **Deviation (executed 2026-11-10):** the Phase 1 review made `ParseCNAAffected` keep an entry whose only identity is its `packageURL` (no vendor, product, package name or versions). CVE 5 does not allow that shape, but dropping it would hide the CVE from a package lookup. The two golden tests for CVE-2026-107832 (`internal/feed/nvd/golden_test.go`, `internal/feed/mitre/golden_test.go`) also changed, beyond the listed files: they pin the parsed entry exactly, and now expect `PackageKey: "npm/fastify"`. Commits c79cd32 and 2899441.

### Task 1.3: Keep every source's CNA copy

**Files:**
- Modify: `internal/merge/resolve.go:46-49,312-336`
- Test: `internal/merge/resolve_test.go:89-117`

**Evidence and behaviour.** `resolveCNAAffected` returns the first source that has entries, so a newer NVD relay is lost whenever MITRE has any copy. Design section 4.3 ("All copies are read"): store the distinct entries of every source. The stale-copy cost is on the safe side, because CNA data cannot clear a version.

**Step 1: Change the test.** `TestResolveCNAAffectedUsesOneSourceWithoutRepeats` pins the behaviour being replaced by the approved design. Rename it `TestResolveCNAAffectedKeepsEverySourcesEntries`. The first case's expectation, for `{nvd, mitre}`, becomes the sorted union of `gadget`, `widget` and `widgetEarlierCopy` (sort by JSON form, as the function does). Keep the second case. Add a case where both sources hold an identical entry, expecting it once, and a case with no CNA data, expecting `nil`.

**Step 2: Run.** `go test ./internal/merge/ -run TestResolveCNAAffected -count=1`. Expected: FAIL.

**Step 3: Implement.**

```go
// resolveCNAAffected returns the distinct CNA affected entries of every source,
// ordered by their JSON form. CNAs repeat whole entries within one record, and the
// MITRE copy and NVD's relay can differ. CNA data can only report a version as
// affected or unresolved, so keeping a stale copy is the safe direction.
func resolveCNAAffected(patches map[string]feed.CanonicalPatch) ([]feed.CNAAffected, error) {
	byKey := make(map[string]feed.CNAAffected)
	for _, p := range patches {
		for _, a := range p.CNAAffected {
			key, err := json.Marshal(a)
			if err != nil {
				return nil, fmt.Errorf("marshal CNA affected entry: %w", err)
			}
			byKey[string(key)] = a
		}
	}
	if len(byKey) == 0 {
		return nil, nil
	}
	entries := make([]feed.CNAAffected, 0, len(byKey))
	for _, key := range slices.Sorted(maps.Keys(byKey)) {
		entries = append(entries, byKey[key])
	}
	return entries, nil
}
```

Remove `cnaPriority` and its comment at `resolve.go:46-49`, which are now false. Keep `otherSources` if anything else uses it.

**Step 4: Run.** `go test ./internal/merge/ -count=1`. Expected: PASS, including `TestIngest_RemovesRepeatedEntriesAndStaysStableOnRemerge`.

**Step 5: Commit.** `git commit -m "fix(merge): keep every source's CNA affected entries"`, with the two files added by name.

### Task 1.4: Record when the NVD walk has finished

**Files:**
- Modify: `internal/feed/nvd/adapter.go:60-64,258-296`
- Test: `internal/feed/nvd/adapter_test.go`

**Evidence and behaviour.** The NVD cursor looks the same at every stage, so nothing can say the first walk finished (design section 5). Desired: the cursor returned with `LastPage` true has `CaughtUp: true`, and every later cursor carries it forward.

**Step 1: Write the failing test.** `TestComputeNextCursor_CaughtUp`: a cursor partway through a window gives `CaughtUp: false`; the "all windows processed" path gives `CaughtUp: true` and `lastPage` true; given an input cursor with `CaughtUp: true`, both the more-pages path and the next-window path keep it `true`. And a JSON round trip: the field marshals as `caught_up`.

**Step 2: Run.** `go test ./internal/feed/nvd/ -run ComputeNextCursor -count=1`. Expected: FAIL.

**Step 3: Implement.** Add `CaughtUp bool `json:"caught_up,omitempty"`` to `Cursor`, documented as: true once a walk has reached the present; a cleared cursor starts false. In `computeNextCursor`, set `CaughtUp: cur.CaughtUp` on the more-pages and next-window literals and `CaughtUp: true` on the caught-up literal. Then search `adapter.go` for every other `Cursor{` literal that is persisted or passed on, including the loop that walks past empty windows, and carry the field in each.

**Step 4: Run.** `go test ./internal/feed/nvd/ -count=1`. Expected: PASS.

**Step 5: Commit.** `git commit -m "feat(nvd): record when a full walk has finished"`, with the two files added by name.

**Phase 1 end:** apply "End of each phase". Update `PLAN.md` Appendix A with the column and indexes. Then merge the pull request to `dev`.

---

## Phase 2 — Full ingest

**Execution Status:** ✅ DONE 2026-11-12. No code ships in this phase. The ingest started 2026-11-10 05:34 UTC and met all four completion signals at 06:56 UTC on 2026-11-12: 2,619,718 CVEs, 3,334,425 source rows, 7,491,658 `cve_affected_packages` rows. The worker ran from `dev` at `2c9fac0`, then at `4356557`, `f663fd7` and `f56bde0` as fixes for problems found on the way merged (PRs #217, #221, #222; see Discoveries). A full backup was taken at completion. The database is kept after Phase 4; it is not scratch.

Starts when Phase 1 is on `dev`. It runs for hours in the background, so Phase 3 proceeds at the same time. No code changes here.

**Step 1: Create a separate database.** Check out the Phase 1 merge commit in its own worktree, and run `bash docker/postgres-tls/generate-cert.sh` there, because the certificates are gitignored and Postgres will not start without them. `docker/compose.yml` fixes its container names, so a different project name alone does not isolate it. Make a copy of `.env` outside the repository with a free `POSTGRES_PORT`, and write a compose override file outside the repository that sets `container_name: cvert-check-ingest-postgres` on the Postgres service and gives it a volume of its own. Start only that service: `docker compose -p cvert-check-ingest -f docker/compose.yml -f <override> --env-file <copy> up -d <postgres service>`. Run `docker compose ... config` first, and confirm the container name, port and volume differ from the development stack. Sharing a volume with the development database is not acceptable.

**Step 2: Confirm credentials exist without printing them.** `NVD_API_KEY` (without it NVD is ten times slower) and the GHSA token the config names. If either is missing, ask Sam. Do not create accounts or keys.

**Step 3: Migrate and run.** In the copy of `.env`, change the port in both `DATABASE_URL` and `DATABASE_URL_MIGRATE` to the scratch port, because compose's `--env-file` does neither of these for host processes, and `DATABASE_URL_MIGRATE` takes precedence for migrations. In one PowerShell session, load the copy with the loop in `CLAUDE.md` §Dev Startup step 3, print the host and port of each URL (never the password) and confirm they are the scratch database, then run `go run ./cmd/cvert-ops migrate`, then `go run ./cmd/cvert-ops worker` in the background, with `FEED_SCHEDULER_ENABLED` on. Log to a file outside the repository.

**Step 4: Wait for the completion signals.** In `feed_sync_state`: `nvd` with `cursor_json->>'caught_up' = 'true'`, `ghsa` with non-empty `cursor_json->>'since'`, `osv` with `cursor_json->>'last_modified'` non-zero, and `mitre` having a recent `last_success_at`. If a feed fails repeatedly, find the root cause, and record it under Discoveries.

**Step 5: Record the data-side measurements** from design section 13 in this plan's Phase 4 notes: largest row counts per package and per CPE product, and how they compare to the 50,000 and 200,000 limits; how many CVEs have `package_key` with no row in `cve_affected_packages`; rows sharing the "several fixes under one `introduced`" shape outside `Root:*` and `GIT`; share of vulnerable CPE rows with no bounds; and, for CVEs with one CNA product and one NVD product and NVD analysis, how often NVD reports a version at or past the CNA's highest clean bound.

> **Verify first (unverified repair, plan review 2026-11-09):** the last measurement above and the write-cost step in Phase 4 were added in the last review wave. Before relying on them, confirm each query returns rows on the ingested data.

**Step 6: Re-measure the query plans** in design section 9 with `EXPLAIN (ANALYZE, BUFFERS)` on real keys, and record the results. Keep this database running for Phase 4.

---

## Phase 3 — The endpoint

**Execution Status:** 🚧 PR OPEN 2026-11-10, waiting for Phase 4. All eleven tasks are done on branch `claude/check-endpoint-734a7a` (cut from `dev` at `d7d8309`, claimed 2026-11-10T05:31Z), in [PR #218](https://github.com/scarson/CVErt-Ops/pull/218) to `dev`, which stays unmerged until Phase 4 reports and Sam decides. Task 3.5 had its own focused review, and Task 3.8 an independent review. The phase end ran `security-review`, `pitfall-check` and `plan-check` (`PLAN.md` §9.2), then four review rounds, each round reviewing the previous round's fixes; Deviations lists every fix. `golangci-lint run` was clean, and `go test ./... -count=1 -timeout=600s` passed at `5c4e025` (39 packages, 0 failures). The branch merges cleanly with `dev` at `4356557`. Decisions for Sam are the Deviations and Discoveries entries marked **For Sam**.

Branch `feat/check-endpoint` from `dev` after Phase 1 merges. (Deviation: the executing session's worktree branch is `claude/check-endpoint-734a7a`; it was not renamed.) Tasks run in order, because each builds on the types of the one before. Tasks 3.2 to 3.8 are pure code with table tests and no database.

### Task 3.1: Version package additions

**Files:**
- Modify: `internal/version/ecosystem.go`, `internal/version/numeric.go`, `internal/feed/ghsa/range.go`
- Create: `internal/version/constraint.go`, `internal/version/constraint_test.go`
- Test: `internal/version/ecosystem_test.go`, `internal/version/numeric_test.go`

**Evidence and behaviour.** A `SEMVER` range in a non-SemVer ecosystem must be compared as SemVer (batch design section 9, rule 3). CNA entries need an ordering chosen by `versionType`. Free-text CNA values such as `>= 20.0.0, <= 20.10.27` use the GHSA range grammar, which lives in `ghsa/range.go` (design section 4.3).

**Step 1: Write the failing tests.** `CheckSemver`: `1.2.3` in `[1.0.0, 2.0.0)` is Affected; `1.2.3-1ubuntu1` is read as SemVer prerelease, and `banana` is `ErrInvalidVersion`. `Order` values: `NumericOrder("1.2", "1.10") < 0`; `NumericOrder("1.2rc1", "1.2")` returns an error; `SemverOrder("1.0.0-rc1", "1.0.0") < 0`; `EcosystemOrder("PyPI")("1.1rc1", "1.1") < 0`; `EcosystemOrder("Root:x")` is `nil`. `ParseRangeExpression`, with the cases in `internal/feed/ghsa/range_test.go` moved over and passing an empty first-patched value for: `>= 20.0.0, <= 20.10.27` gives `{20.0.0, "", 20.10.27}`; `0.5.6 - 1.13.2` is not parsed.

**Step 2: Run.** `go test ./internal/version/ -count=1`. Expected: FAIL.

**Step 3: Implement.**
- In `ecosystem.go`: `func CheckSemver(version string, r Range) (Status, error)`, using `semverSyntax` and `compareInEcosystem("npm", a, b)`.
- `type Order func(a, b string) (int, error)`, returning an error when either side cannot be read. `NumericOrder` wraps `numericSyntax` and `compareNumeric`. `SemverOrder` uses `semverSyntax`. `EcosystemOrder(ecosystem string) Order` returns `nil` when `lookupEcosystem` fails, otherwise a closure over `Compare(ecosystem, a, b)`.
- Move `rangeConstraint`, `zeroVersion` and the body of `parseVulnerableRange` to `constraint.go` as `func ParseRangeExpression(ecosystem, raw, firstPatched string) (Range, bool)`, returning `version.Range`. `ghsa.parseVulnerableRange` becomes a one-line call converting to `rangeBounds`, so GHSA's behaviour and its tests stay unchanged. Keep the existing explanatory comment with the moved code.

**Step 4: Run.** `go test ./internal/version/ ./internal/feed/ghsa/ -count=1`. Expected: PASS.

**Step 5: Commit.** `git commit -m "feat(version): add SemVer checks, orderings and a shared range grammar"`, with the files added by name.

### Task 3.2: Parse request items

**Files:**
- Create: `internal/check/doc.go`, `internal/check/input.go`, `internal/check/input_test.go`

**Evidence and behaviour.** Design sections 3.1 to 3.4 and 11 (`error.code` values).

```go
// Item is one parsed request item. Exactly one of Package or Product is set
// unless Error is.
type Item struct {
	Index   int
	ID      string
	Package *PackageRef
	Product *ProductRef
	Version string
	Error   *ItemError
}

type PackageRef struct{ Ecosystem, Name string }

// ProductRef holds lower-cased CPE attributes, as written, with escapes kept.
type ProductRef struct{ Part, Vendor, Product string }

type ItemError struct{ Code, Message string }

// RawItem is the request body's item.
type RawItem struct {
	ID        string `json:"id,omitempty"`
	Purl      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	CPE       string `json:"cpe,omitempty"`
	Version   string `json:"version,omitempty"`
}

func ParseItem(index int, raw RawItem) Item
```

**Step 1: Write the failing tests.** One row for each limit in design section 3.4 (`value_too_long`); each `error.code`; a control character such as NUL in `id`, `name`, `cpe` or `version` is `invalid_characters`, because PostgreSQL rejects NUL in a query parameter and one bad item must not fail the request; a purl plus `version` in one item is `invalid_form`; `ecosystem` without `name` is `invalid_form`; `Debian` alone is `ecosystem_release_required` (from `ecosystem.NeedsRelease`); `Debain:13` is `invalid_ecosystem`. CPE: splits on unescaped colons only, so `cpe:2.3:a:foo\:bar:baz:*:*:*:*:*:*:*:*` has vendor `foo\:bar`; a `*` or `-` in `part`, `vendor` or `product` is `invalid_cpe`; fewer than 13 components is `invalid_cpe`; the CPE's own version is used when `version` is absent; both given and different is `conflicting_version`; both absent, or the version is `*` with no `version`, is `version_required`; the CPE is lower-cased. `v24.22.0` and `V24.22.0` in CPE form become `24.22.0`; `vfoo` stays `vfoo`; a `v` in a package-form version is not removed. A purl with a `download_url` or a `vcs_url` qualifier is `unsupported_repository`.

**Step 2: Run, Step 3: Implement, Step 4: Run.** `go test ./internal/check/ -count=1`. Failing first, then passing. `ParseItem` calls `ecosystem.FromPurl` and maps `*ecosystem.PurlError` to `ItemError`. `ParseItem` refuses `download_url` and `vcs_url` itself, before it calls `FromPurl`. `FromPurl` also maps stored CNA URLs, which keep their key with these qualifiers.

**Step 5: Commit.** `git commit -m "feat(check): parse version check request items"`, with the files added by name.

### Task 3.3: Package range verdicts

**Files:**
- Create: `internal/check/verdict.go`, `internal/check/packages.go`, `internal/check/packages_test.go`

**Evidence and behaviour.** Design section 4.1, including its table of row outcomes and the rule for combining rows.

```go
// Verdict is one advisory's answer for one component. The zero value is
// CannotEvaluate, so an unset verdict never reads as "not affected".
type Verdict int

const (
	CannotEvaluate Verdict = iota
	Affected
	NotAffected
)

// Reason values are the API's reason enumeration (design section 11).
type Reason string

// Matched is one range that contains the version, for the response.
type Matched struct {
	Evidence, CPE, Introduced, Fixed, LastAffected string
}

// Outcome is what one source says about one advisory.
type Outcome struct {
	Verdict    Verdict
	Reason     Reason
	Matched    []Matched
	Candidates []string // upper bounds of ranges reporting Affected
	Ranges     []Bound  // every range, for validating fix candidates
	Comparable bool     // at least one row was compared
}

// Bound is one range with the order that reads it.
type Bound struct {
	Range version.Range
	Check func(version string, r version.Range) (version.Status, error)
}

// PackageRow is one cve_affected_packages row.
type PackageRow struct {
	CVEID, Ecosystem, PackageName, RangeType, Introduced, Fixed, LastAffected string
}

// workMeter stops comparison work when the request's context ends, because a
// context cannot interrupt pure computation. Every loop that compares versions
// calls Tick once per range or candidate and leaves the loop when it returns false.
type workMeter struct {
	ctx    context.Context
	ticks  int
	err    error
	onTick func() // test hook, nil in production
}

func newWorkMeter(ctx context.Context) *workMeter { return &workMeter{ctx: ctx} }

// Tick checks the context every 1,000 calls and reports whether work may continue.
func (m *workMeter) Tick() bool {
	if m.err != nil {
		return false
	}
	if m.onTick != nil {
		m.onTick()
	}
	m.ticks++
	if m.ticks%1000 == 0 {
		m.err = m.ctx.Err()
	}
	return m.err == nil
}

// Err reports the context's error at the moment it is asked, so a short request
// cancelled between multiples of 1,000 ticks is still noticed.
func (m *workMeter) Err() error {
	if m.err == nil {
		m.err = m.ctx.Err()
	}
	return m.err
}

func EvaluatePackageRows(m *workMeter, ecosystem, ver string, rows []PackageRow) Outcome
```

An outcome produced after `Tick` returned false is discarded by `Evaluate`, which returns `m.Err()` (Task 3.8).

> **Verify first (unverified repair, plan review 2026-11-09):** `Err` reading the context, and `readEntry`'s order returning an error after `Tick` is false, were added in the last review wave. Test it: cancel the context before a one-row evaluation, confirm `Evaluate` returns `context.Canceled`; then make `Err` return only `m.err`, confirm that test fails, and restore it.

**Step 1: Write the failing tests.** One row for each row of the section 4.1 table, and each combination: Affected if any row is; Not affected only with at least one Not affected and no cannot-evaluate; `GIT` rows ignored beside other rows; `GIT` only gives `commit_ranges_only`; `SEMVER` range in `Debian:13` is read as SemVer and a version SemVer cannot read is `invalid_version`; a `Root:x` ecosystem is `unknown_version_scheme`; no bounds is `invalid_range`; the `(0, A)` and `("", B)` shape gives Affected with no fix claimed below A and cannot evaluate at or above A; a `last_affected` bound is not a candidate.

**Step 2 to 4.** Failing, then implement `EvaluatePackageRows`, then passing. Map `errors.Is(err, version.ErrUnknownEcosystem)` to `unknown_version_scheme`, `ErrInvalidVersion` to `invalid_version`, and `ErrInvalidRange` to `invalid_range`.

**Step 5: Commit.** `git commit -m "feat(check): decide verdicts from package ranges"`, with the files added by name.

### Task 3.4: NVD CPE verdicts

**Files:**
- Create: `internal/check/cpe.go`, `internal/check/cpe_test.go`

**Evidence and behaviour.** Design section 4.2. `func EvaluateCPERows(m *workMeter, ver string, rows []CPERow) Outcome`, where `CPERow` holds `CVEID`, `CPE` (normalised) and the four `version*` bounds. The CPE's own version component comes from splitting `CPE` on unescaped colons, with the function Task 3.2 wrote.

**Step 1: Write the failing tests.** One row for each row of the section 4.2 table: `*` with bounds, where `versionEndExcluding` becomes `Fixed` and `versionEndIncluding` becomes `LastAffected`; `versionStartExcluding` stored as an inclusive `Introduced`; a literal version with no range; `*` with no bounds and `-` as `no_version_bounds`. A version like `1.24rc1` is `invalid_version`. Row with `update` narrowing still applies (`microsoft:.net:11.0.0:preview1` reports `11.0.0` Affected).

**Steps 2 to 5.** Failing, implement, passing, then `git commit -m "feat(check): decide verdicts from NVD CPE ranges"`.

### Task 3.5: Read CNA entries

**Files:**
- Create: `internal/check/cna.go`, `internal/check/cna_test.go`

**Evidence and behaviour.** Design section 4.3 is the authority. This is the code most likely to produce a wrong "not affected", so it is written out in full here. Implement it as written. If a test seems to need a different result, stop and raise it with Sam.

**Step 1: Write the failing tests.** A table test with one row for each row of the section 4.3 result table and each of these, all from design section 12:

| Entry | Version | Reading |
|---|---|---|
| `{1.0, lt 2.0, affected, semver}` | `1.5` | Affected, candidate `2.0` |
| same | `2.0`, `0.9` | NoStatement |
| The shape of CVE-2024-7347: `{1.25.0, lt 1.27.1, affected}`, changes at 1.26.2 and 1.27.1 to `unaffected` | `1.26.0` | Affected, candidate `1.26.2` |
| same | `1.26.2` | NoStatement |
| same | `1.26.5` | Indeterminate |
| CVE-2021-44228 values (`custom`, lower `2.0-beta9`, upper `log4j-core*`) | `2.14.0` | Affected, candidate `2.15.0` |
| same | `2.0.1` | Indeterminate (first segment's lower bound unreadable) |
| same | `2.17.0` | Indeterminate |
| `{1.0, lt 3.0, unknown}`, change to `affected` at 2.0 | `1.5` | Indeterminate |
| same | `2.5` | Affected |
| `{1.0, lt 3.0, unaffected}`, change to `affected` at 2.0, to `unaffected` at 2.5 | `1.5` | NoStatement |
| same | `2.2` | Affected, candidate `2.5` |
| same | `2.7` | Indeterminate |
| changes given in reverse order | | same as sorted |
| a change whose `at` the comparator cannot read | above the lower bound | Indeterminate |
| `{1, lt *, affected}`, change to `unaffected` at 2 | `1.5`, `2`, `2.5` | Affected, NoStatement, Indeterminate |
| `{12.0, lt 12.*, affected, semver}` | `12.22.12` | Indeterminate |
| same | `13.0.0` | NoStatement |
| `{1.0.0, lt 2.*, affected, semver}` | `1.5.0`, `2.9.0`, `3.0.0` | Indeterminate, Indeterminate, NoStatement |
| `{6.6.1, lte 6.6.*, unaffected, semver}` | `6.6.5` | NoStatement |
| `{1.0rc1, lt 2.0, unaffected, custom}` | `1.5` | NoStatement (a first `unaffected` segment can condemn nothing, inside it or not) |
| `{1.0, lt 2.0, unaffected, custom}` | `1.1rc1` (the comparator cannot read the version) | NoStatement |
| `{1.0, lt 2.0, unaffected, versionType: deb}` | `1.5` | NoStatement |
| `{1.0rc1, lt 2.0, affected, custom}` | `1.5` | Indeterminate |
| `{1.0rc1, lte 2.0, affected, custom}` | `2.0` | Indeterminate |
| same | `2.1` | NoStatement |
| `{1, lt 2, lte 3, affected}` (both upper bounds, which the CVE schema does not allow) | `2.5` | Indeterminate |
| `{unspecified, affected}`, change to `affected` at 2 | `3` | Indeterminate |
| `{0.5.6 - 1.13.2, affected}` (CVE-2017-7529) | `1.0.0` | Indeterminate |
| `{>= 20.0.0, <= 20.10.27, affected}` | `20.5.0` | Affected, no candidate |
| `{>= 1.0.0, affected, custom}` | `1.5.0` | Affected, no candidate |
| same | `0.9.0` | NoStatement |
| `{1.0, lte 2.*, affected, semver}` | `2.9.0`, `3.0.0` | Indeterminate, NoStatement |
| `{unspecified, affected}`, `{n/a, affected}`, `{*, affected}`, `{"", affected}` | any | NoVersionInfo |
| `{<commit>, lt <commit>, affected, git}` | any | NoVersionInfo |
| `{1.0, lt 2.0, affected, versionType: deb}` (a type with no comparator) | `1.5` | Indeterminate |
| `{26.5.0, lte 26.5.0, affected}` | `26.4.0` | NoStatement |
| `{1.2.3, affected}` | `1.2.3` | Affected, no candidate |
| `{0, lt 2.0, affected, semver}` | `0.0.1-alpha` | Affected, candidate `2.0` |

Also a `TestReadCNAEntries` for "strongest wins" across entries.

**Step 2: Run.** `go test ./internal/check/ -run CNA -count=1`. Expected: FAIL.

**Step 3: Implement.**

```go
// CNAVersion mirrors one stored versions[] element.
type CNAVersion struct {
	Version         string      `json:"version"`
	LessThan        string      `json:"less_than"`
	LessThanOrEqual string      `json:"less_than_or_equal"`
	Status          string      `json:"status"`
	VersionType     string      `json:"version_type"`
	Changes         []CNAChange `json:"changes"`
}

type CNAChange struct {
	At     string `json:"at"`
	Status string `json:"status"`
}

// Reading is what a CNA entry says about one version, weakest first, so the
// strongest of several entries is their maximum.
type Reading int

const (
	NoStatement Reading = iota
	NoVersionInfo
	Indeterminate
	AffectedReading
)

// reading is one entry's answer, with the fix it names when it reports Affected.
type reading struct {
	result    Reading
	candidate string
}

var (
	lineWildcard = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)\.\*$`)
	freeTextForm = regexp.MustCompile(`[<>=]`)
)

func orderFor(versionType string) version.Order {
	switch versionType {
	case "semver":
		return version.SemverOrder
	case "python":
		return version.EcosystemOrder("PyPI")
	case "maven":
		return version.EcosystemOrder("Maven")
	case "rpm":
		return version.EcosystemOrder("Red Hat")
	case "custom", "":
		return version.NumericOrder
	}
	return nil
}

func hasNoVersionInformation(e CNAVersion) bool {
	if e.VersionType == "git" {
		return true
	}
	if e.LessThan != "" || e.LessThanOrEqual != "" || len(e.Changes) > 0 {
		return false
	}
	switch strings.ToLower(e.Version) {
	case "", "unspecified", "n/a", "unknown", "*":
		return true
	}
	return false
}

// bound is one edge of a segment.
type bound struct {
	value     string
	readable  bool
	wildcard  bool // the edge is a line wildcard; value is the first version past the line
	unlimited bool // no upper edge, or a bare "*"
	open      bool // a free-text range stated no upper edge, so every higher version is inside
}

type segment struct {
	start, end   bound
	endInclusive bool
	status       string
}

func readEntry(m *workMeter, ver string, e CNAVersion) reading {
	if hasNoVersionInformation(e) {
		return reading{result: NoVersionInfo}
	}
	// An entry that is wholly unaffected can condemn nothing, whether or not its
	// bounds or the version can be read.
	if e.Status == "unaffected" && len(e.Changes) == 0 {
		return reading{result: NoStatement}
	}
	read := orderFor(e.VersionType)
	if read == nil {
		return reading{result: Indeterminate}
	}
	order := func(a, b string) (int, error) {
		if !m.Tick() {
			return 0, m.Err()
		}
		return read(a, b)
	}
	if _, err := order(ver, ver); err != nil {
		return reading{result: Indeterminate}
	}
	e, openEnded := expandFreeText(e)

	segments, ok := buildSegments(e, openEnded, order)
	if !ok {
		return unsortableReading(ver, e, order)
	}

	// A segment whose two edges can be read decides the answer outright.
	for i, s := range segments {
		if !s.start.readable || !s.end.readable || s.end.wildcard {
			continue
		}
		if !s.contains(ver, order) {
			continue
		}
		switch {
		case s.status == "affected":
			return reading{result: AffectedReading, candidate: fixCandidate(segments, i, e)}
		case s.status != "unaffected":
			return reading{result: Indeterminate}
		case i == 0, atStart(ver, s, order):
			return reading{result: NoStatement}
		default:
			return reading{result: Indeterminate}
		}
	}

	if first := segments[0]; first.status == "unaffected" && (len(segments) == 1 || isBelow(ver, segments[1].start, order)) {
		return reading{result: NoStatement}
	}
	for i, s := range segments {
		if i > 0 && s.status == "unaffected" && atStart(ver, s, order) {
			return reading{result: NoStatement}
		}
	}
	for _, s := range segments {
		if s.possiblyContains(ver, order) {
			return reading{result: Indeterminate}
		}
	}
	return reading{result: NoStatement}
}
```

Supporting functions, all in `cna.go`:

- `expandFreeText(e) (CNAVersion, bool)`: when `e` has no upper bound and no changes and `freeTextForm` matches `e.Version`, parse with `version.ParseRangeExpression("", e.Version, "")`. On success, replace `Version`, `LessThan` and `LessThanOrEqual` from the result (`Introduced`, `Fixed`, `LastAffected`), and return true when the result has no upper bound, as for `>= 1.0.0`. On failure leave it, so the value is unreadable and reads as Indeterminate.
- Lower-bound normalisation: a `Version` ending in `.*` drops that suffix before segments are built.
- `buildSegments(e, openEnded, order)`: sorts a copy of `e.Changes` by `At` using `order`, and returns `ok=false` if `order` cannot read any `At`. The first segment starts at `e.Version`, status `e.Status`; each change starts one with its status (an empty status is treated as `unknown`). The last segment's `end` comes from `upperBound(e, order)`, with `endInclusive` true for a `LessThanOrEqual` that is not a wildcard. When `openEnded` is true, `end` is `bound{readable: true, open: true}`. Otherwise, with no upper bound and no changes, the entry is a single version: `end` is `e.Version`, inclusive. With no upper bound and changes, the last segment is unlimited.
- `upperBound`: `*` gives `unlimited`, which is not `readable`, so a segment ending there is never decided by the first loop. A value matching `lineWildcard` gives `wildcard: true`, `value` = the prefix with its last number incremented (`12` becomes `13`, `1.2` becomes `1.3`), `readable: true`. Otherwise `readable` is whether `order(value, value)` succeeds. An entry that sets both `lessThan` and `lessThanOrEqual` has an upper bound that is not `readable`.
- `newBound` for a start: `"0"` is `readable: true`, and comparisons treat it as below everything, as `version.Check` does with `introducedAtStart`.
- `s.contains(ver, order)`: at or above `start`, and either `end.open` or below `end` (or equal when `endInclusive`). The caller has confirmed both edges are readable.
- `s.possiblyContains(ver, order)`: `ver` is not provably below a readable `start`, and not provably past a readable or wildcard `end`. Past means at or above an exclusive end, and above an inclusive one. An unlimited or open end is never passed.
- `isBelow(ver, b, order)` and `atStart(ver, s, order)`: require `b.readable`, and return false on any comparison error.
- `fixCandidate(segments, i, e)`: if segment `i+1` exists and its status is `unaffected`, its start value; if `i` is the last segment and `e.LessThan` is set and is neither `*` nor a line wildcard, `e.LessThan`; otherwise `""`.
- `unsortableReading(ver, e, order)`: Indeterminate when the lower bound cannot be read, or `ver` is at or above it. Otherwise NoStatement.

`func ReadCNAEntries(m *workMeter, ver string, entries []CNARow) CNAResult`, where `CNARow` has `CVEID`, `Vendor`, `Product`, `Versions []CNAVersion`, and `CNAResult` has the strongest `Reading`, `Candidates` and `Matched`. It leaves its loop when `m.Err()` is non-nil. `readEntry` takes the meter too, and wraps the order it obtains so each comparison calls `m.Tick()`, which covers `buildSegments` and its sort. `defaultStatus` is never read.

`func CNARangeCount(entries []CNARow) int` adds `2 + len(v.Changes)` for each `versions` element `v` (the element, plus its segments), with no comparisons. `Evaluate` calls it before any reading, for the 1,000-range limit in Task 3.8, so an oversized entry is refused before its changes are sorted.

**Step 4: Run.** The Step 2 command. Expected: PASS.

**Step 5: Commit.** `git commit -m "feat(check): read CNA version entries as segments"`, with the two files added by name.

### Task 3.6: Combine sources, and find CNA rows

**Files:**
- Create: `internal/check/combine.go`, `internal/check/names.go`, `internal/check/combine_test.go`, `internal/check/names_test.go`

**Evidence and behaviour.** Design sections 4.4 (the five steps), 4.5 (lookups and the table) and 4.6 (package rows).

`func Combine(primary Outcome, hasPrimaryRows bool, cna CNAResult) Outcome` implements the five steps, in order, with reasons `cna_indeterminate` and `cna_cannot_clear`.

`names.go`:

```go
// CNAName is one way to find CNA rows for a CPE product.
type CNAName struct {
	Vendor, Product string
	Prefix          bool
}

type cnaMapping struct {
	Names    []CNAName
	Fragment string // product-name fragment for the nearby-name check
	Vendor   string // CNA vendor for the nearby-name check
}

var cnaNames = map[string]cnaMapping{ /* design section 4.5 table, keyed by "vendor:product" */ }

// NamesFor returns every CNA name to look up: always the CPE's own, plus the
// table's. mapped is true when a table row exists.
func NamesFor(p ProductRef) (names []CNAName, mapping cnaMapping, mapped bool)
```

**Step 1: Write the failing tests.** `Combine`: every row of the section 4.4 worked examples, each of the five steps alone, and "an entry with no version information does not stop step 4". `NamesFor`: `nodejs:node.js` includes its direct name and both table names; `openssl:openssl` returns the direct name, with `_` read as a space and `mapped` false; `nginx:nginx` includes direct `nginx`/`nginx`; `microsoft:.net` holds prefix `.net ` and matches `.NET 6.0` and `.NET 9.0 runtime`.

**Steps 2 to 5.** Failing, implement, passing, then `git commit -m "feat(check): combine sources and find CNA names"`.

### Task 3.7: Fix reporting

**Files:**
- Create: `internal/check/fix.go`, `internal/check/fix_test.go`

**Evidence and behaviour.** Design section 7. `func PickFix(m *workMeter, ver string, candidates []string, order version.Order, ranges []Bound, cna func(candidate string) Reading) (fixed string, fixMajor *string)`, calling `m.Tick()` once per candidate-and-range check. It returns `""` and `nil` when no candidate passes. `order` is `version.EcosystemOrder(ecosystem)` for a package item and `version.NumericOrder` for a CPE item. A `nil` order, for an ecosystem with no comparator, returns `""` and `nil`.

**Step 1: Write the failing tests.** Node `24.22.0` gives `24.22.1`, `same`; two sources (`1.2.3`, `1.2.4`) containing `1.2.0` give `1.2.4`; a candidate that a CNA entry reports as Indeterminate is rejected; a candidate another range reports cannot evaluate is rejected; a candidate `order` cannot read (`1.1rc1` beside numeric) gives `""`; Node `20.0.0` against `(, 22.23.4)` gives `22.23.4`, `different`; Node `23.1.0` against `[23.0.0, 24.22.1)` gives `24.22.1`, `different`; `1:2.0` and `1:2.1` give `same`, compared after the epoch; a version with no leading number gives `unknown`. A counting `order` stub shows the loop stops at the first passing candidate.

**Steps 2 to 5.** Failing, implement, passing, then `git commit -m "feat(check): report the lowest fix for each advisory"`.

### Task 3.8: Item status, feeds and the response

**Files:**
- Create: `internal/check/evaluate.go`, `internal/check/evaluate_test.go`, `internal/check/feeds.go`, `internal/check/feeds_test.go`, `internal/check/advisory.go`, `internal/check/advisory_test.go`

**Evidence and behaviour.** Design sections 4.7 (status order), 5 (completeness), 6 (`cve_ids`, exploit data, counts) and 8 (retraction).

- `feeds.go`: `func FeedStatuses(rows []FeedRow, now time.Time) map[string]FeedStatus`. A feed is complete when its walk finished and `last_success_at` is within 7 days. GHSA: `cursor_json.since` non-empty; OSV: `cursor_json.last_modified` non-zero; NVD: `cursor_json.caught_up` true. Dependencies: distro item `osv`; other package item `ghsa`, `osv`, `nvd`; CPE item `nvd`.
- `advisory.go`: `func CVEIDsFor(advisoryID string) []string`, from section 6: `CVE-` gives itself; `UBUNTU-CVE-*`, `DEBIAN-CVE-*` and `ALPINE-CVE-*` give the CVE in the ID; everything else gives an empty, non-nil slice.
- `evaluate.go`: `func Evaluate(ctx context.Context, items []Item, data Candidates, feeds map[string]FeedStatus, enrichment map[string]CVEEnrichment) (Results, error)`, which makes one `workMeter` for the request, passes it to every function above, and returns `m.Err()` as soon as it is non-nil, with no partial `Results`. `Results` carries the JSON field names of design section 11.

```go
// Keys is what the store must read, distinct across the request. Each slice's
// position is the key index that rows in Candidates refer to.
type Keys struct {
	Packages       []PackageKey   // Ecosystem and folded name
	CPEPrefixes    []CPEKey       // Lo "cpe:2.3:a:nodejs:node.js:", Hi "cpe:2.3:a:nodejs:node.js;", Prefix (see below)
	CNANames       []CNANameKey   // see below
	CNAPackageKeys []string       // ecosystem.PackageKeyFor; non-distro package items only
	CNANear        []CNANearKey   // V, FullVendor, Fragment, VendorLo "cpe:2.3:a:microsoft:", VendorHi "cpe:2.3:a:microsoft;"
}

// Candidates holds the rows read for each key, in Keys order, and whether a key
// reached its per-key limit.
type Candidates struct {
	Packages       []KeyRows[PackageRow]
	CPEs           []KeyRows[CPERow]
	CNANames       []KeyRows[CNARow]
	CNAPackageKeys []KeyRows[CNARow]
	CNANear        []KeyRows[CNANearRow]
}

type KeyRows[T any] struct {
	Rows     []T
	Overflow bool
}

// KeysFor returns the distinct keys of the valid items.
func KeysFor(items []Item) Keys
```

A `CNANameKey` is built from lower-cased names, cut to 256 characters by rune count to match SQL `left`. `V` is the cut vendor. For an exact name, `Lo` is the cut product and `Hi` is `Lo + "\x01"`, built after the cut so a long name cannot collapse the interval. For a prefix, `Lo` is the cut prefix and `Hi` is that prefix with its last rune incremented. `FullVendor` is the whole lower-cased vendor, and `FullProduct` is the whole lower-cased product, or `""` for a prefix key.

A `CPEKey` matches `cve_cpe_matches_check_idx`, which holds the first 512 characters of `cpe_normalized` (migration 000061). `Prefix` is the whole CPE prefix. `Lo` is `Prefix` cut to 512 characters by rune count, to match SQL `left`, and `Hi` is `Lo` with its last rune incremented, built after the cut. The statement rechecks `Prefix` against the whole value.

Each row type gains `Status string` (the `cves.status` of its CVE), and retraction is decided in `Evaluate` by `isRetracted`, using `lower(status)` in `rejected` or `withdrawn`. A row in `CNANear` that is the same row as one of the item's `CNANames` rows (same CVE, vendor and product) is dropped. Any other `CNANear` row makes its CVE's advisory cannot evaluate, `cna_name_uncertain`, unless that advisory already reports Affected.

> **Verify first (unverified repair, plan review 2026-11-09):** this filter was narrowed from CVE level to row level in the last review wave. Test it with `.net 9.0` and `microsoft .net runtime` on one CVE with no Microsoft CPE row: the advisory must be `cna_name_uncertain`. Then filter by CVE alone, confirm that test fails, and restore the filter.

A CPE item is `mapped` for `cna_product_not_mapped` when `NamesFor` reports a table row or any `CNANames` row was found. Package rows and CPE rows are the `primary` passed to `Combine`, and distro items use no CNA rows.

`CVEEnrichment` holds `Severity`, `CVSSv3Score`, `InCISAKEV` and `EPSSScore`, keyed by CVE row ID. The `severity` and `cvss_v3_score` of an advisory come from its own `advisory_id` row. `in_cisa_kev` and `epss_score` come from its `cve_ids` rows.

**Step 1: Write the failing tests.** Each row of the section 4.7 status table, in order, including precedence between adjacent rows; a retracted-only distro package is `no_advisory_found`; zero rows in a distro ecosystem is `distro_package_not_found`; item over 50,000 rows is `too_many_candidates` with no advisories; advisory over 1,000 ranges is `too_many_ranges`, including one CNA row holding 10,000 `changes` items, for which a test asserts through the meter's tick count that no comparison ran; Not-affected advisories are counted and not listed; advisories capped at 100, Affected first, then KEV, then score, with `advisories_truncated`; `matched_ranges` capped at 20 with `matched_ranges_total`; KEV true if any of `cve_ids`, EPSS highest; empty `cve_ids` gives `null` for both; each feed-dependency row, including a distro item complete with no GHSA cursor, and a 7-day-stale feed; item `reason` is null when the status comes from an advisory. `cna_name_uncertain` advisories, `cna_product_not_mapped` as a status when otherwise clean and as a warning on `no_advisory_found`.

Identical items reuse one evaluation; a test asserts this through the `workMeter` tick count. A cancellation test sets `onTick` to cancel the context partway through an item with thousands of rows, and asserts `Evaluate` returns `context.Canceled` and no results.

**Steps 2 to 5.** Failing, implement, passing, then `git commit -m "feat(check): assemble item status from advisory verdicts"`.

### Task 3.9: The store read

**Files:**
- Modify: `internal/store/store.go:114-140`
- Create: `internal/store/check.go`, `internal/store/check_test.go` (package `store_test`), `internal/store/export_test.go` if one does not exist

**Evidence and behaviour.** Design sections 5, 9 and 10. All statements run in one `REPEATABLE READ`, read-only snapshot. `withOrgRawTx` uses default isolation at `store.go:121`.

Read `dev/implementation-pitfalls.md` §2.17 (transaction helper selection), ARCH-45 and ARCH-46. Do not seed CVE rows with raw SQL (`dev/testing-pitfalls.md` §7): use `SeedCorpus` or `merge.Ingest` with targeted patches.

**Step 1: Write the failing tests** (integration, `testutil.NewTestDB`):
- Each of the five statements returns rows for a seeded key, and none for another.
- A CPE key `foo:bar` does not return `foo:barbaz`, and `foo\:bar` does not return `foo\:barbaz`.
- A CNA prefix key returns `.NET 9.0 runtime`, and an exact key does not return a longer name.
- A product name over 256 characters: two names sharing the first 256, and only the exact one matches.
- A CPE key over 512 characters: two stored CPEs sharing the first 512, and only the one that starts with the whole prefix is returned.
- The nearby-name statement returns a row whose CVE has only a CPE row for another vendor, and none where the CVE has a CPE row for this vendor.
- `TestReadCheckCandidates_OneSnapshot`: call `readCheckCandidates` with an `afterStatement` callback that commits a change from another connection after the first statement, and assert the second statement sees the original state. `testutil` imports `store`, so these tests are in package `store_test`, and `export_test.go` exposes `readCheckCandidates` and `checkLimits` to them.
- Limits, by calling `readCheckCandidates` with lowered `checkLimits`: a key at its limit has `Overflow` true and other keys are complete; a request over the row limit or the byte limit returns `ErrCandidateLimit`.
- Status, enrichment and feed rows are read in the snapshot.

**Step 2: Run.** `go test ./internal/store/ -run ReadCheck -count=1`. Expected: FAIL.

**Step 3: Implement.** In `store.go`, extract `withOrgRawTxOptions(ctx, orgID, opts *sql.TxOptions, fn)`. `withOrgRawTx` calls it with `nil`, and add:

```go
// withOrgSnapshotTx is withOrgRawTx in one read-only REPEATABLE READ snapshot, for
// reads that must not mix states from before and after a concurrent merge.
func (s *Store) withOrgSnapshotTx(ctx context.Context, orgID uuid.UUID, fn func(*sql.Tx) error) error {
	return s.withOrgRawTxOptions(ctx, orgID, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, fn)
}
```

`check.go` holds `func (s *Store) ReadCheckCandidates(ctx context.Context, orgID uuid.UUID, keys check.Keys) (check.Candidates, map[string]check.CVEEnrichment, []check.FeedRow, error)`, which calls the unexported `readCheckCandidates(ctx, orgID, keys, limits checkLimits, afterStatement func(name string))` with the default limits and a nil callback. `checkLimits` holds `KeyRows` (50,000), `RequestRows` (200,000) and `RequestBytes` (128 MiB). Array parameters use `pq.Array`. Rows are counted as they arrive, and a key's rows past `KeyRows` set its `Overflow`. Passing a request limit stops reading and returns `ErrCandidateLimit`. The per-item 50,000 limit, across the keys one item uses, is applied by `Evaluate` in Task 3.8.

Statements. The last parameter of each is `limits.KeyRows + 1`:

```sql
-- Packages. <folded> is ecosystem.FoldedNameSQL("q.ecosystem", "q.package_name").
SELECT k.ord, p.cve_id, p.ecosystem, p.package_name, p.range_type, p.introduced, p.fixed, p.last_affected, c.status
FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS k(eco, name, ord)
CROSS JOIN LATERAL (
  SELECT q.* FROM cve_affected_packages q
  WHERE q.ecosystem = k.eco AND <folded> = k.name
  LIMIT $3
) p
JOIN cves c ON c.cve_id = p.cve_id;

-- CPE. lo is 'cpe:2.3:a:nodejs:node.js:'; hi is 'cpe:2.3:a:nodejs:node.js;', both
-- cut to 512 characters as CPEKey defines them. prefix is the whole prefix.
SELECT k.ord, m.cve_id, m.cpe_normalized, m.version_start_including, m.version_start_excluding,
       m.version_end_including, m.version_end_excluding, c.status
FROM unnest($1::text[], $2::text[], $3::text[]) WITH ORDINALITY AS k(lo, hi, prefix, ord)
CROSS JOIN LATERAL (
  SELECT q.* FROM cve_cpe_matches q
  WHERE left(q.cpe_normalized, 512) COLLATE "C" >= k.lo COLLATE "C"
    AND left(q.cpe_normalized, 512) COLLATE "C" <  k.hi COLLATE "C"
    AND starts_with(q.cpe_normalized, k.prefix)
    AND q.vulnerable
  LIMIT $4
) m
JOIN cves c ON c.cve_id = m.cve_id;

-- CNA names. v, lo and hi are as CNANameKey defines them. full_product is empty for
-- a prefix key, which needs no recheck of the product.
SELECT k.ord, a.cve_id, a.vendor, a.product, a.versions, c.status
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[]) WITH ORDINALITY
     AS k(v, lo, hi, full_vendor, full_product, ord)
CROSS JOIN LATERAL (
  SELECT q.* FROM cve_cna_affected q
  WHERE left(lower(q.vendor), 256) COLLATE "C" = k.v COLLATE "C"
    AND left(lower(q.product), 256) COLLATE "C" >= k.lo COLLATE "C"
    AND left(lower(q.product), 256) COLLATE "C" <  k.hi COLLATE "C"
    AND lower(q.vendor) = k.full_vendor
    AND (k.full_product = '' OR lower(q.product) = k.full_product)
  LIMIT $6
) a
JOIN cves c ON c.cve_id = a.cve_id;

-- CNA package keys.
SELECT k.ord, a.cve_id, a.versions, c.status
FROM unnest($1::text[]) WITH ORDINALITY AS k(key, ord)
CROSS JOIN LATERAL (
  SELECT q.* FROM cve_cna_affected q WHERE q.package_key = k.key LIMIT $2
) a
JOIN cves c ON c.cve_id = a.cve_id;

-- Nearby names. vendor_prefix is 'cpe:2.3:a:microsoft:', vendor_hi is 'cpe:2.3:a:microsoft;'.
SELECT k.ord, a.cve_id, a.vendor, a.product, c.status
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[]) WITH ORDINALITY
     AS k(v, full_vendor, frag, vendor_prefix, vendor_hi, ord)
CROSS JOIN LATERAL (
  SELECT q.cve_id, q.vendor, q.product FROM cve_cna_affected q
  WHERE left(lower(q.vendor), 256) COLLATE "C" = k.v COLLATE "C"
    AND lower(q.vendor) = k.full_vendor
    AND strpos(lower(q.product), k.frag) > 0
    AND NOT EXISTS (
      SELECT 1 FROM cve_cpe_matches m
      WHERE m.cve_id = q.cve_id
        AND m.cpe_normalized COLLATE "C" >= k.vendor_prefix COLLATE "C"
        AND m.cpe_normalized COLLATE "C" <  k.vendor_hi COLLATE "C"
    )
  LIMIT $6
) a
JOIN cves c ON c.cve_id = a.cve_id;
```

Then enrichment, for every advisory ID read and every ID `check.CVEIDsFor` derives from them: `SELECT cve_id, severity, cvss_v3_score, in_cisa_kev, epss_score FROM cves WHERE cve_id = ANY($1)`. Then the feeds: `SELECT feed_name, cursor_json, last_success_at FROM feed_sync_state WHERE feed_name = ANY($1)`.

Retraction: pass `c.status` through as each row's `Status`. Do not filter rejected or withdrawn CVEs in the join, or `counts.retracted` cannot be computed.

**Step 4: Run.** Step 2's command. Expected: PASS. Run `go test ./internal/store/ -run 'Org|ReadCheck' -count=1` as well, since `withOrgRawTx` changed.

**Step 5: Commit.** `git commit -m "feat(store): read version check candidates in one snapshot"`, with the files added by name.

### Task 3.10: The handler and the API contract

**Files:**
- Create: `internal/api/check.go`, `internal/api/check_test.go`
- Modify: `internal/api/server.go` (route near `:350`, field and constructor near `:54,:92`), `internal/api/openapi_spec.go:47-52`, `internal/api/openapi_security.go:116`, `openapi.json`, `web/src/lib/api/schema.d.ts`

**Evidence and behaviour.** Design sections 3.4 (error table), 9 (limits), 10 (authorisation) and 11 (contract). `replaceWatchlistItemsHandler` at `watchlists.go:631` is the pattern for an org handler, body decoding and capped items. `acquireArgon2` at `server.go:552` is the pattern for the semaphore.

**Step 1: Write the failing tests.**
- Role: viewer can call; no credentials is 401.
- Errors: each row of the section 3.4 table. A body over 1 MiB, through the router with `middleware.RequestSize`, gives 413. One invalid item among valid ones gives 200 with `status: "invalid"`. Over 500 items gives 422. All semaphore slots held gives 503 with `Retry-After`. Request limit passed gives 422 with `candidate_limit_exceeded`. A cancelled context gives 503.
- `TestOpenAPISpec_CheckItemsCapMatchesHandler`, in the manner of `TestOpenAPISpec_ReplaceItemsCapMatchesHandler`.
- Item contents are not logged: capture `slog` output during a request, and assert no `purl`, `cpe` or package name appears.

**Step 2: Run.** `go test ./internal/api/ -run 'Check|OpenAPI' -count=1`. Expected: FAIL.

**Step 3: Implement.**
- Route inside the org group: `r.With(srv.RequireOrgRole(RoleViewer)).Post("/check", srv.checkComponentsHandler)`.
- Constants `maxCheckItems = 500`, `maxConcurrentChecks = 4`, `checkTimeout = 30 * time.Second`, and `checkSem chan struct{}` built in the constructor.
- Handler order: acquire slot or 503; `io.ReadAll(r.Body)`, returning 413 when `errors.As` finds an `*http.MaxBytesError`, because `middleware.RequestSize` only wraps the body and `decodeJSON` would report that as 400; put the bytes back as `r.Body`; decode; validate cap; `check.ParseItem` for each; build `check.Keys`; `ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)`; `ReadCheckCandidates`; release the database; `check.Evaluate` with that `ctx`, returning 503 if it reports the context ended; write JSON.
> **Verify first (unverified repair, plan review 2026-11-09):** the 413 path was added in the last review wave. Remove the `errors.As` branch, confirm the oversized-body test gets 400 and fails, and restore it.

- `operationAccess`: `"POST /orgs/{org_id}/check": roleOp("viewer")`.
- `registerCheckSpecOps`, called from `registerAllSpecOps`: operation ID `check-components`, default status 200, and named body types `CheckRequest`, `CheckItem`, `CheckResults`, `CheckItemResult`, `CheckAdvisory`, `CheckMatchedRange`, `CheckComponent`, `CheckCounts`, `CheckItemError`, `CheckFeedStatus`. Do not name a body `CheckComponentsResponse`: it collides with the generated client type. Enumerations as `enum` tags, from design section 11. Descriptions say that `no_advisory_found` means "nothing known", that `not_affected` means "not in any analysed or CNA-named advisory held", that counts are of records, and that `fixed_version` is "the lowest version the advisory data no longer reports as affected".
- Regenerate `openapi.json`, from the Bash tool and not PowerShell, with `GENERATE_OPENAPI=1 go test -run '^TestOpenAPISpec$' ./internal/api/ -count=1`, then the web schema with `cd web && npm run generate-api`. CI fails if `schema.d.ts` differs.

**Step 4: Run.** The Step 2 command, plus `cd web && npm run type-check`. Expected: PASS.

**Step 5: Commit.** `git commit -m "feat(api): add the version check endpoint"`, with the files added by name.

### Task 3.11: End-to-end cases on real data

**Files:**
- Create: `internal/api/check_integration_test.go`
- Modify: `internal/feed/osv/testdata/golden/all.zip`, `golden_material_hashes.json` and its pinned counts

**Evidence and behaviour.** Design section 12 is the case list. Every row becomes a test. `testutil.SeedCorpus` writes no feed cursors, so tests needing `data_complete: true` call `UpsertFeedSyncState`.

**Step 1: Add golden records.** Add `UBUNTU-CVE-2026-109618`, `UBUNTU-CVE-2026-109619` and `USN-8948-1`, fetched from `api.osv.dev`, to `all.zip`. Update `golden_material_hashes.json` and corpus counts with the additions only. **Existing pins must not move:** if one does, stop and find out why.

**Step 2: Write the tests.** One subtest per row of the section 12 table, each naming its row. Targeted patches go through `merge.Ingest`.

**Step 3: Run.** `go test ./internal/api/ -run CheckIntegration -count=1`. Fix code, not expectations; a row whose expectation seems wrong goes to Sam.

**Step 4: Break test, run once and not committed.** Change step 5 of `Combine`, so that with no primary rows any CNA result except Affected gives Not affected. Confirm the two rows "CNA must not clear" and "`changes[]` must not clear" fail. Restore the file with `git checkout -- internal/check/combine.go`, and rerun.

**Step 5: Commit.** `git commit -m "test(check): cover the version check endpoint on real records"`, with the files added by name.

**Phase 3 end:** run the `security-review` skill on the route, `pitfall-check`, and `plan-check` against `PLAN.md` §9.2, then apply "End of each phase". Add the endpoint to `PLAN.md` §16 and Appendix B. Open the pull request, and leave it unmerged until Phase 4 reports.

---

## Phase 4 — Measurement and merge

**Execution Status:** ✅ COMPLETE 2026-11-13, on branch `claude/check-endpoint-734a7a`. Steps 1 to 3 ran once on a copy of the partial ingest, then as the go/no-go run on a copy of the complete ingest on 2026-11-12 (Phase 4 notes below). Step 4: reported to Sam on 2026-11-12; Sam had two independent reviews decide, and their consensus changed the roll-up (Deviations), built in `0241f0d` and re-measured. Step 5: PR #218 merged to `dev` as `d6919bf` on 2026-11-12, after a review of the whole PR. Step 6: measured on 2026-11-13 (Phase 4 notes, "Index write cost"); the copy is dropped and the kept ingest is unchanged.

Needs Phase 2's database and Phase 3's branch.

**Step 1: Point the Phase 3 build at the ingested database.** Load the same `.env` copy as Phase 2 Step 3, and confirm the URL host and port the same way, before running `go run ./cmd/cvert-ops serve` from the Phase 3 branch, with `METRICS_PORT` and `LISTEN_ADDR` set to free ports, because the Phase 2 worker still holds the default metrics port. Mint an API key through the application's own flow on that scratch database, for this measurement only.

(Deviation: `serve` reads a copy, not the ingest database itself. `serve` always starts a worker pool, whatever `FEED_SCHEDULER_ENABLED` says, so on the ingest database it would claim the Phase 2 worker's queued feed jobs. It would run them with this branch's feed code, which lacks the GHSA token rename (#216) and the feed body cap (#217). Each run copies `cvert_ops` with `pg_dump` into a database `cvert_phase4` in the same cluster, deletes its pending and running jobs, and runs `ANALYZE`; `serve` runs with `FEED_SCHEDULER_ENABLED=false`, `LISTEN_ADDR=:18080` and `METRICS_PORT=19090`. The copy takes under 4 minutes. The scripts live outside the repository.)

**Step 2: Check the acceptance examples:** Node `24.22.0` returns CVE-2026-111497 with fixed `24.22.1`; `24.22.1` returns nothing for it; `php8.5` `8.5.4-0ubuntu1.4` in `Ubuntu:26.04:LTS` returns the PHP CVEs with fixed `8.5.4-0ubuntu1.5`, and shows `in_cisa_kev: true` on the `UBUNTU-CVE-*` records.

**Step 3: Measure the go/no-go in design section 13.** For Node, PHP, .NET, nginx, OpenSSL and PostgreSQL, at a current patched version and at one older version: item status, advisories by verdict and reason, and which CVEs hold each item at `cannot_evaluate`. Report the `cna_product_not_mapped` and `cna_name_uncertain` names, and whether they are worth table rows.

**Step 4: Report to Sam, and stop.** Sam decides whether the item roll-up stands. No threshold is set in advance. If it changes, that is a design change: amend the design, record it under Deviations, and add it to the Phase 3 pull request.

**Step 5: Merge** the Phase 3 pull request after Sam's decision.

**Step 6: Measure index write cost on a copy, and keep the ingest.** Sam keeps the full ingest as lasting data: the database `cvert_ops`, the Docker volume `cvert-check-ingest-pgdata`, its container, and the locked `check-ingest` worktree, whose files the container mounts. None of them is changed or removed. (Deviation, 2026-11-10: this step first measured on the ingest database and then removed the Phase 2 containers and worktree.) Measure on a copy: `cvert_phase4`, re-made from `cvert_ops` with `pg_dump`, or a restore of a backup from the kept-data backups folder. On the copy, set the NVD cursor back 7 days, run a worker pointed at the copy until it catches up, and record CVEs merged per minute from its log. Drop the four indexes from Task 1.2 on the copy and repeat. Record both rates here, then drop the copy database.

### Phase 4 notes

#### Go/no-go run, 2026-11-12, complete ingest

A copy of the complete ingest: 2,619,748 CVEs, 7,491,658 package rows, 3,244,484 CPE rows and 684,174 CNA rows. The copy was migrated to version 61 (Deviations), and `serve` was built at `7dae4bf` with JIT off. Every response reported `data_complete: true`.

**Acceptance (Step 2): pass.**
- Node `24.22.0` lists CVE-2026-111497 as Affected, with fixed `24.22.1`. Node `24.22.1` does not list it.
- `php8.5` `8.5.4-0ubuntu1.4` in `Ubuntu:26.04:LTS` lists `UBUNTU-CVE-2026-109618` and `UBUNTU-CVE-2026-109619` as Affected, each with fixed `8.5.4-0ubuntu1.5` and `in_cisa_kev: true`. It also lists `USN-8948-1` (fixed `8.5.4-0ubuntu1.5`) and `UBUNTU-CVE-2026-17545` (no fix).

**Items (Step 3).** Every product's current release answers `cannot_evaluate`, with no advisory Affected. Every older version answers `affected`, except OpenSSL `1.1.1w`, which answers `invalid_version` on 322 of its 328 advisories (5 `cna_indeterminate`, 1 `cna_name_uncertain`): a letter release is not dotted numbers (design section 3.3). The current releases are later than NVD's highest fix bounds (Deviations).

| Current release | Affected / Cannot evaluate / Not affected | What holds it at `cannot_evaluate` |
|---|---|---|
| Node `26.13.1` | 0 / 60 / 186 | 59 `cna_cannot_clear`, 1 `cna_indeterminate` |
| PHP `8.5.12` | 0 / 11 / 730 | 6 `cna_indeterminate` (15 free-text entries), 3 `no_version_bounds`, 1 `invalid_range` (CVE-2006-3017), 1 `cna_cannot_clear` |
| .NET SDK `10.0.404` | 0 / 91 / 132 | 42 `cna_indeterminate`, 30 `cna_name_uncertain`, 19 `cna_cannot_clear` |
| nginx `1.31.7` | 0 / 50 / 36 | 27 `cna_cannot_clear`, 17 `cna_name_uncertain`, 4 `cna_indeterminate`, 2 `invalid_range` |
| OpenSSL `4.0.4` | 0 / 90 / 238 | 85 `cna_indeterminate`, 4 `cna_cannot_clear`, 1 `cna_name_uncertain` |
| PostgreSQL `18.6` | 0 / 36 / 174 | 28 `cna_indeterminate` (50 free-text entries), 7 `cna_cannot_clear`, 1 `no_version_bounds` |

Older versions:

| Version | Affected / Cannot evaluate / Not affected |
|---|---|
| Node `26.12.1` | 15 / 45 / 186 (15 CVEs the Node CNA fixed in `26.13.1`, not yet analysed by NVD) |
| Node `24.22.1`, `18.20.0` | 15 / 45 / 186; 27 / 46 / 173 |
| PHP `7.4.33` | 5 / 11 / 725 |
| .NET `10.0.15` (runtime), `10.0.14`, `8.0.0` | 12 / 80 / 131; 24 / 68 / 131; 114 / 49 / 60 |
| nginx `1.29.3`, `1.20.0` | 18 / 32 / 36; 24 / 29 / 33 |
| OpenSSL `3.5.4`, `1.1.1w` | 62 / 62 / 204; 0 / 328 / 0 |
| PostgreSQL `18.5`, `13.0` | 28 / 36 / 146; 70 / 13 / 127 |

The six current releases have 338 `cannot_evaluate` advisories. By reason:

- **`cna_indeterminate`, 166.** The CNA entry cannot be read for the version, and where NVD has analysed the CVE it says Not affected. Design section 15 keeps these at cannot evaluate. The entries are of three kinds:
  - free text: `Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1)`, `9.2.x before 9.2.22`;
  - ranges with letter versions: `1.1.1` lessThan `1.1.1t`, version type `custom`;
  - entries with `changes`.

  The leading-number rule decides letter ranges for NVD bounds (`4.0.4` is past `1.1.1t`), but it does not apply to CNA entries. Free text would stay undecided under any rule.
- **`cna_cannot_clear`, 117.** The CNA names the product, but NVD has no row for that product. Either NVD has not analysed the CVE, which covers most recent CVEs, or it analysed it under another product (CVE-2021-22959 is under `llhttp:llhttp`). 57 of the 144 Node CNA rows belong to CVEs with no NVD CPE row at all. The Node CNA states the affected lines (4 to 23 for CVE-2025-23083) and does not name 26, but design section 4.4 lets a CNA entry alone condemn a version, never clear one.
- **`cna_name_uncertain`, 48.** Nearby CNA names that are other products:
  - .NET: `Microsoft Visual Studio 2022 version 17.14`, `Microsoft Visual Studio 2026 version 18.10`, and the `Microsoft .NET Framework` 3.5 to 4.8.1 entries;
  - nginx: `NGINX Plus`, `NGINX JavaScript`, `NGINX Ingress Controller`, `NGINX Gateway Fabric`;
  - OpenSSL: `OpenSSL extension of Ruby (Git trunk)`.

  Name table rows marking these as other products would answer them from the item's own data. No item answered `cna_product_not_mapped`.
- **`no_version_bounds`, 4, and `invalid_range`, 3.** Rows from 1999 to 2006 for PHP, PostgreSQL and nginx.

**Linux kernel.**
- CPE `o:linux:linux_kernel` has 165,349 vulnerable rows.
- A single kernel from `6.12.50` up is answered:
  - `6.12.50`: 2,546 Affected, 94 Cannot evaluate, 12,648 Not affected;
  - `7.2.7`: 8 Affected, 94 Cannot evaluate, 15,186 Not affected.
- `6.6.95`, `6.1.140` and `5.15.170` answer `too_many_candidates`.
- The 10-kernel LTS fleet answers `too_many_candidates`, with or without `6.8.0-45-generic`, because its floor is `5.15.170`.
- Every kernel version carries 73 `no_version_bounds` advisories.
- OSV's package key `Linux`/`kernel` (88,857 rows) answers `too_many_candidates`.
- The CNA name `linux`/`linux` holds 36,476 rows, under the 50,000-row limit.

**Cost.** Each request is one item list, run three times with JIT off:

| Request | Time | Allocated |
|---|---|---|
| The 22 go/no-go items | 0.47 to 0.57 s | 83 MiB |
| 50 Firefox versions | 0.96 to 0.98 s | 502 MiB |
| One kernel `6.12.50` | 0.79 to 0.91 s | 107 MiB |
| 500 items over the largest CPE products | 8.1 to 8.3 s | 3.97 GiB |
| 300 kernel versions | 0.40 s | 55 MiB |

- The 500-item request left 605 to 687 MiB resident. 322 of its items answered `affected`, 128 `cannot_evaluate` and 50 `too_many_candidates`.
- All 300 kernel versions answered `too_many_candidates`.

**JIT.** The same binary was run with `SET LOCAL jit = on` in place of `off`, three runs each. JIT on was never faster:

| Request | JIT on | JIT off |
|---|---|---|
| Go/no-go items | 1.04 to 1.16 s | 0.47 to 0.57 s |
| 500 heavy items | 8.8 to 9.1 s | 8.1 to 8.3 s |
| 50 Firefox versions | 0.96 to 1.06 s | 0.96 to 0.98 s |
| Kernel `6.12.50` | 0.83 to 0.87 s | 0.79 to 0.91 s |

Allocations were the same. The check read keeps `jit = off`.

**Data** (`03-phase4-extra.sql` on the copy):
- **Ubuntu Pro rows with no standard row:** 27,145 `UBUNTU-CVE-*` records under the plain Pro streams (347,410 rows); see Discoveries. The figure first recorded here, 34,326 records (649,816 rows), counted the FIPS and Realtime sub-streams too.
- **CPE products with vulnerable rows under both `a:` and `o:`:** 237 of 121,741, covering 41,280 CVEs. The largest are Cisco ASA software (14,535 `o:` rows, 47 `a:`), VMware ESXi (8,999 / 38) and Xen (2,833 / 22).
- **CNA entries with a `*` lower bound and an upper bound** (read as indeterminate): 983 entries in 591 CVEs, 978 of them `affected`. The largest names are MySQL Server (161 CVEs), Zephyr (59) and MediaWiki (38).
- **`SEMVER` package rows:** 264,987 in 233,040 records:

  | Ecosystem | Rows |
  |---|---|
  | npm | 219,919 |
  | Bitnami | 26,152 |
  | Go | 12,457 |
  | crates.io | 3,864 |
  | Julia | 2,054 |
  | Hex | 467 |
  | SwiftURL | 74 |

  None are in `Root:*` or `GitHub Actions`.
- **Stored CNA package keys with whitespace:** none.

#### After the roll-up change, 2026-11-12, `0241f0d`

The same 22 items on the same copy, `serve` built at `0241f0d` with JIT off. Acceptance passes, as before.

| Item | Before (`7dae4bf`) | After (`0241f0d`) |
|---|---|---|
| Node `26.13.1` | `cannot_evaluate`, 0 / 60 / 186 | `unresolved`, 0 / 60 / 189 |
| PHP `8.5.12` | `cannot_evaluate`, 0 / 11 / 730 | `unresolved`, 0 / 11 / 730 |
| .NET SDK `10.0.404` | `cannot_evaluate`, 0 / 91 / 132 | `cannot_evaluate`, `sdk_version_not_comparable`, 0 / 80 / 134 |
| nginx `1.31.7` | `cannot_evaluate`, 0 / 50 / 36 | `unresolved`, 0 / 25 / 61 |
| OpenSSL `4.0.4` | `cannot_evaluate`, 0 / 90 / 238 | `unresolved`, 0 / 48 / 279 |
| PostgreSQL `18.6` | `cannot_evaluate`, 0 / 36 / 174 | `unresolved`, 0 / 36 / 174 |
| OpenSSL `1.1.1w` | `cannot_evaluate`, 0 / 328 / 0 | `cannot_evaluate`, `invalid_version`, 0 / 327 / 0 |
| nginx `1.29.3` | `affected`, 18 / 32 / 36 | `affected`, 20 / 21 / 45 |

Counts are Affected / Cannot evaluate / Not affected.

- nginx: `cna_cannot_clear` fell from 27 to 2, because the NVD rows under `f5:nginx_open_source` are now read.
- OpenSSL `4.0.4`: `cna_indeterminate` fell from 85 to 43 through the letter-suffix rule for CNA bounds, and the Ruby extension's `cna_name_uncertain` is gone.
- .NET: `cna_name_uncertain` fell from 30 to 12 and `cna_indeterminate` from 42 to 16, since the .NET Framework entries are no longer read as .NET; those CVEs now answer `cna_cannot_clear` (52).
- Ubuntu, probes on the copy:
  - A `Ubuntu:Pro:22.04:LTS` item for `openssl` `3.0.2-0ubuntu1.25` now lists the 14 standard-stream USNs, with `fix_ecosystem` `Ubuntu:22.04:LTS`.
  - A standard item for `ruby-rack` lists 23 advisories whose fix is published only in Pro.
  - A `FIPS-updates` item for `curl`, which has no rows there, answers `distro_stream_incomplete`.

#### Index write cost (Step 6), 2026-11-13

**Result:** on this host, the four check lookup indexes slow NVD merges by less than the variation between identical runs. The two runs with the indexes averaged about 7% slower than the two without, but the slowest and fastest runs of each case overlap. The cost is too small to measure here and is no reason to change the indexes.

**Method.**
- One `pg_dump` of the kept ingest (`cvert_ops`, 2,619,748 CVEs) was taken at 2026-11-13T00:55Z. Each run restored it into `cvert_phase4`, migrated it to version 61, and ran `VACUUM ANALYZE`.
- The runs without the indexes then dropped the four indexes from Task 1.2: `cve_affected_packages_check_idx`, `cve_cpe_matches_check_idx`, `cve_cna_affected_check_idx` and `cve_cna_affected_package_key_idx`.
- The NVD cursor was set to the fixed window 2026-11-06T00:55Z to 2026-11-13T00:55Z. A `worker` built at `453ec86` (the code merged as `d6919bf`) ran against the copy, with the feed scheduler and retention cleanup off, and one NVD job was queued at a time until a job ended `success`.
- The copy already held the window's data, but this still exercises the indexes. The merge deletes and re-inserts every child row of each CVE it touches (packages, CPEs, CPE matches, CNA entries), for every feed's rows, whether or not anything changed.
- Merge time: each merge's transaction start is in `cve_raw_payloads.ingested_at`. The gap between consecutive NVD rows is one merge, and gaps of 5 s or more (NVD fetches) are left out.

| Run (in order) | Indexes | Merges | Merge time | Merges per minute | Median merge | p99 merge |
|---|---|---|---|---|---|---|
| 1 | with | 11,961 | 360 s | 1,994 | 21 ms | 190 ms |
| 2 | without | 11,961 | 240 s | 2,990 | 14 ms | 144 ms |
| 3 | with | 11,987 | 263 s | 2,735 | 15 ms | 148 ms |
| 4 | without | 11,987 | 339 s | 2,122 | 20 ms | 171 ms |

Means: 2,364 merges per minute with the indexes, 2,556 without. Runs 3 and 4 read 26 more records than runs 1 and 2. NVD returned them for the same window, presumably because they had been modified again inside it. Run 4's NVD fetches failed twice with HTTP 524, and the job was queued again each time. Those waits are not in its merge time.

**What limits the result.** Docker Desktop on this host is shared with other sessions, and runs of the same case differed by about 40%. The kept Phase 2 worker, which writes to `cvert_ops` in the same cluster, ran one 6-second NVD job (82 records) between runs 1 and 2, and nothing else during the runs. Telling a cost of about 10% apart from this noise would take more runs on a quiet host. The question that matters here is whether the indexes cost too much, and the answer is no, so that was not done.

After the runs, `cvert_phase4` and the dump were dropped. `cvert_ops`, its volume, its container and the `check-ingest` worktree are unchanged.

#### Phase 2 measurements (Phase 2 Steps 5 and 6), complete ingest

Measured on 2026-11-12 at 07:13 UTC on the complete ingest, before Phase 4's own runs: 2,619,746 CVEs; 7,491,658 package rows; 3,244,484 CPE rows (2,649,617 vulnerable); 684,184 CNA rows. Both queries the plan review flagged (M2 and M6, the last measurement in Step 5) return rows.

**Largest keys against the limits** (design section 9: 50,000 rows for one item, 200,000 for one request):

- Package keys: OSV's `Linux`/`kernel` has 88,857 rows, over the item limit. The next largest are Ubuntu and Debian kernel builds, at 19,800 to 20,300 rows each. 1 package key is over 50,000.
- CPE products (vulnerable rows): `o:linux:linux_kernel` 165,349; `o:cisco:ios` 69,369; `o:juniper:junos` 63,845. These 3 are over 50,000. Then come `a:mozilla:firefox` (38,199) and `a:google:chrome` (37,623).
- CNA names: `n/a`/`n/a` 144,540 (the lookup excludes `n/a`); `linux`/`linux` 36,476; the largest Microsoft product 7,406.
- An item for the Linux kernel by package always answers `too_many_candidates`. A CPE item reads only the rows at or above its request's lowest version for that product (the CPE row filter), so whether it passes the limit depends on that version (kernel results in the go/no-go run above). A request with the 10 largest package keys among 300 read 234,046 rows, over the 200,000 request limit.

**CNA package keys with no package rows:** 4,255 CVEs have a CNA entry with a `package_key`. 3,905 of them have no `cve_affected_packages` row under that CVE ID:

| Purl type | CVEs |
|---|---|
| npm | 511 |
| Maven | 453 |
| PyPI | 347 |
| Go | 340 |
| Packagist | 163 |
| crates.io | 111 |
| NuGet | 15 |
| RubyGems | 14 |
| Key with no purl type | 1,951 |

573 of the 3,905 have no GHSA or OSV source at all. Stored keys containing whitespace: 0, so trimming is not needed now.

**Several fixes under one `introduced`, outside `Root:*` and `GIT`:** 3,117 rows in 984 advisories with no ecosystem, OSS-Fuzz 1,383 rows, PyPI 518, Linux 428, and Alpine releases 11 to 123 rows each. Inside `Root:*` and `GIT`: 84,335 rows.

**Index use** (`pg_stat_user_indexes` since the stats were last reset: the ingest worker plus read-only measurement runs, no API traffic). The check indexes are used:

| Index | Scans |
|---|---|
| `cve_affected_packages_check_idx` | 986 |
| `cve_cna_affected_check_idx` | 324 |
| `cve_cpe_matches_check_idx` | 300 |
| `cve_cna_affected_package_key_idx` | 6 |

`cve_affected_packages_eco_pkg_idx` was scanned 5 times; migration 000061 dropped it.

**Vulnerable CPE rows with no version bounds:** 381,011 of 2,649,617 rows (14.4%). 39,344 of 122,336 products (32.2%) have at least one.

**NVD past the CNA's clean bound** (CVEs with one CNA product and one NVD product, NVD analysed):

| Step | CVEs |
|---|---|
| One product on each side | 124,944 |
| CNA entry has `lessThan` | 40,544 |
| CNA bound is numeric | 26,168 |
| NVD bound is numeric too | 25,945 |
| NVD reports a version at or past the CNA's highest clean bound | 3,645 (14.1%) |

The examples are mostly Linux kernel CVEs where the CNA's bound is a series such as `6.2` and NVD's is a release such as `7.2.6`.

**Query plans (Step 6).** `EXPLAIN (ANALYZE, BUFFERS)` on the statements in `internal/store/check.go` at PR #218's `6fdc2bb`, with real keys. That is before the CPE row filter (`08b6595`) and before the bounded CPE key (`7dae4bf`), so the CPE row reads every vulnerable row of each product. Each lookup ran twice under a custom plan (second figure warm) and once under a generic plan:

| Lookup | Keys | Rows | Custom plan, first / second | Generic plan | Index |
|---|---|---|---|---|---|
| Packages | 300 (the 10 largest and 290 random) | 234,046 | 1.16 s / 0.93 s | 1.05 s | `cve_affected_packages_check_idx` |
| CPE | 100 products (the 5 largest and 95 random) | 226,944 | 0.90 s / 0.65 s | 0.29 s | `cve_cpe_matches_check_idx` |
| CNA names | 105 (100 exact, 5 vendor prefixes) | | 26 ms / 10 ms | 10 ms | `cve_cna_affected_check_idx` |
| CNA package keys | 100 | | 7 ms | | `cve_cna_affected_package_key_idx` |
| CNA near names | the 3 largest vendors | 70,160 | 0.80 s / 0.65 s | 0.80 s | `cve_cna_affected_check_idx` |
| CVE search, ecosystem and package filter, largest key | 1 | | 177 ms | | `cve_affected_packages_check_idx` |

Every lookup reads its keys through the index named. The second packages run still read 182,000 buffers from outside Postgres's shared buffers, so these times depend on the OS file cache of a 34 GB database.

#### Provisional run, 2026-11-10T10:22Z, partial ingest

**This is not the go/no-go result.** The copy held 302,045 CVEs, 455,644 package rows, 1,215,035 CPE rows and 107,041 CNA rows. Only `ghsa` had finished. NVD had 110,934 records, and its rows for these six products stop around 2021 (the highest Node fix bound was `10.4.1`). MITRE had reached `CVE-2017-0908`, and OSV had not reached Ubuntu. The acceptance examples cannot pass yet: CVE-2026-111497 has no NVD or MITRE row, and there are no `Ubuntu:*` rows. Build `6fdc2bb`.

The finding below does not depend on the ingest finishing. The rows that hold patched versions at `cannot_evaluate` belong to old CVEs whose NVD analysis is already stored, and finishing the ingest adds CVEs; it removes none.

**Items (CPE form unless noted).** Every one answered `cannot_evaluate`.

| Item | Affected / Cannot evaluate / Not affected | What holds it at `cannot_evaluate` |
|---|---|---|
| Node `24.22.0`, `24.22.1`, `18.20.0` | 0 / 5 / 46 | 5 `invalid_range`: CVE-2016-2086, -2216, -3956, -5325, -7099. Each lists exact NVD versions that are not dotted numbers |
| PHP `8.4.14`, `7.4.33` | 0 / 57 / 539 | 53 `invalid_range` (exact versions such as `php:2.0b10`, CVE-1999-0058 onwards), 3 `no_version_bounds`, 1 `cna_indeterminate` |
| .NET `9.0.11`, `6.0.0` | 0 / 0 / 3 | Item reason `data_incomplete` (MITRE had not reached Microsoft's .NET CVEs) |
| nginx `1.29.3`, `1.20.0` | 0 / 2 / 25 | 2 `cna_indeterminate`: CVE-2017-7529 (`0.5.6 - 1.13.2`), CVE-2011-4968 |
| OpenSSL `3.5.4` | 0 / 167 / 20 | 166 `invalid_range`: 90 from exact letter versions (`1.0.1a`), 76 from letter bounds (`< 1.0.2zf`) |
| OpenSSL `1.1.1w` | 0 / 187 / 0 | `invalid_version` on all 187: a letter release is not dotted numbers (design section 3.3) |
| PostgreSQL `18.1`, `13.0` | 0 / 5 / 97 | 2 `cna_indeterminate` (CVE-2017-7546, CVE-2017-7548: `9.2.x before 9.2.22`), 2 `invalid_range`, 1 `no_version_bounds` |
| Linux kernel `6.12.0` (`o:linux:linux_kernel`) | 0 / 0 / 0 | Item reason `too_many_candidates`: 82,061 vulnerable rows, over the 50,000 per-key limit, with NVD unfinished |
| `php8.5` `8.5.4-0ubuntu1.4`, `Ubuntu:26.04:LTS` | 0 / 0 / 0 | `distro_package_not_found` (no Ubuntu rows yet) |

**A candidate rule, measured but not implemented.** When a CPE row's version or bound is not dotted numbers, compare the item version with the bound's leading dotted-number part, and treat the comparison as decided only when the two differ at a component both have. `8.4.14` is not `2.0b10`, and `3.5.4` is past `1.0.2zf`, while `1.0.2` against `1.0.2zf` stays undecided. Run over the advisories above (`phase4_prefix_sim.py`, outside the repository), this decides as Not affected all 5 Node, 52 of 53 PHP (CVE-2006-3017 stays), all 166 OpenSSL `3.5.4` and both PostgreSQL `invalid_range` advisories, and decides none as Affected. Node and OpenSSL `3.5.4` would then answer `not_affected`. PHP, nginx and PostgreSQL would stay at `cannot_evaluate` on `cna_indeterminate` and `no_version_bounds`, which are design section 15's decisions. This is a design change to section 4.2 and needs Sam.

Sam chose it on 2026-11-10 (Deviations). Re-run on the same copy at `6ef031b`:

| Item | Cannot evaluate / Not affected, before | After | What still holds it |
|---|---|---|---|
| Node `24.22.0`, `24.22.1`, `18.20.0` | 5 / 46 | 0 / 51 | Item reason `data_incomplete` only (NVD and OSV unfinished) |
| PHP `8.4.14`, `7.4.33` | 57 / 539 | 5 / 591 | 3 `no_version_bounds`, 1 `invalid_range` (CVE-2006-3017), 1 `cna_indeterminate` (CVE-2014-3622, `5.6.x before 5.6.1`) |
| nginx `1.29.3`, `1.20.0` | 2 / 25 | 2 / 25 | 2 `cna_indeterminate` (`0.5.6 - 1.13.2`, `through 1.6.2`) |
| OpenSSL `3.5.4` | 167 / 20 | 10 / 177 | 9 `cna_indeterminate` (CVE-2016-7053 to CVE-2018-0739: `All 0.9.8`, `Fixed in OpenSSL 1.1.0h (Affected 1.1.0-1.1.0g)`), 1 `cna_name_uncertain` |
| PostgreSQL `18.1`, `13.0` | 5 / 97 | 4 / 98 | 3 `cna_indeterminate` (`9.2.x before 9.2.22`), 1 `no_version_bounds` |

After the rule, what holds patched versions is mostly CNA free text from 2011 to 2018 that NVD has analysed as not affecting them. Design section 15 keeps those at cannot evaluate when NVD says Not affected ("An indeterminate CNA entry when NVD says Not affected"); that is the next go/no-go question for Sam.

**Linux kernel and a date cutoff.** Sam asked whether a publication-date cutoff could bring `linux_kernel` under the 50,000-row key limit. On the copy, 7 CVEs published before 2015 have unbounded kernel rows (`*` or `-` with no bounds, such as CVE-1999-0524 and CVE-2008-4609). A 2015 cutoff would drop them, and an item they now hold at cannot evaluate could answer `not_affected`, so a date cutoff can give a wrong "not affected". A version-aware filter in the lookup does not: keeping only rows whose leading numbers allow the item's version keeps 14 of 82,061 rows for `6.12.0`. It needs the CPE key to carry the version's leading number, and a way to keep "NVD has analysed this CVE" for CVEs whose rows are all filtered out, or design section 4.4 reads them as unanalysed (`cna_cannot_clear`). Built on 2026-11-10 in a different form; see the next paragraph.

**Rows below the version** (built 2026-11-10, `08b6595`; design sections 4.2 and 9, amended the same day; Sam's decision). The CPE lookup leaves unread the rows whose ranges lie wholly below the floor of the item's version, and returns one row per CVE counting them.

- **Why "below" and not "leading numbers allow the version".** Fix reporting checks each candidate against every range of the advisory. A range above the version can reject a candidate (`[2.0, 3.0)` rejects the `2.0` of `[1.0, 2.0)`), so leaving it out could change `fixed_version`. A range wholly below the version answers Not affected for every version at or above it, so for every candidate. Only those are left out.
- **One key per product, floor = the lowest version asked.** Every item of a product shares one read, as before the rule. The floor is at or below each item's version, which is all the rule needs. The first form (one key per two-component floor) read the product once per floor; see the Deviations entry. The price: what a key returns depends on the request's other items of that product. An old version, or a version that is not dotted numbers, beside new ones makes the read as large as before the rule, and if it passes 50,000 rows every item of the product answers `too_many_candidates`, as before the rule. Verdicts never depend on it.
- **Rows read, kernel `6.12.0`:** 82,061 before (the lookup stopped at 50,001 and the item answered `too_many_candidates`); after, 2,064: 14 stored rows and 2,050 CVE counts standing for 82,047 rows.
- **`EXPLAIN (ANALYZE, BUFFERS)` on the copy**, JIT off, custom / generic plan, before and after: kernel `6.12` 81 / 24 ms and 238 / 231 ms; kernel with no floor 77 / 25 ms and 86 / 85 ms; Firefox `130.0` 61 / 21 ms (35,051 rows) and 96 / 99 ms (1,455 rows); Chrome `120.0` 48 / 17 ms (31,425) and 100 / 95 ms (1,546); PHP `8.3` 33 / 9 ms (16,090) and 49 / 46 ms (596); OpenSSL `3.0` 7 / 3 ms (4,299) and 13 / 13 ms (247). The full table is in design section 9. The read is slower; what it saves is the evaluation of the rows it no longer returns (100 to 150 ms and about 54 MiB per item per 35,000 rows, under "Cost" below). The endpoint itself was not re-timed.
- **Not helped:** a request whose lowest version of a large product is old (300 kernel versions from `2.0.0`: all `too_many_candidates`, as before). A version that is not dotted numbers (`6.8.0-45-generic`, as `uname -r` prints it) first cleared the product's floor, which put a 10-version LTS kernel fleet back at `too_many_candidates` as soon as it was added; such a version now leaves the floor to the others and answers `invalid_version` on every advisory, as it did from every row (Deviations). Kernel `2.6.32` asked alone is now answered from 34,782 rows.
- **End to end** (`serve` on the copy; before is the `6ef031b` binary): 1 kernel item `6.12.0`, 0.13 s refused to 0.25 to 0.34 s answered, 57 to 4 MiB allocated; 50 Firefox versions, 4.5 s and 2.7 GiB to 0.20 to 0.24 s and 29 MiB; 500 items over 10 large products, 19.3 s and 11.4 GiB to 1.7 to 2.0 s and 1.1 GiB; 300 kernel versions, 2.0 s and 5.1 GiB to 2.1 to 2.2 s and 5.4 GiB, HTTP 200 with every item `too_many_candidates` in both. All 851 items answer the same in both binaries, field for field, except the single kernel item that was over its limit.
- **Limits.** A CVE's count row counts as one row towards the 50,000 and 200,000 limits, so the kernel's 2,050 CVEs today use 2,050 of them. That number grows with the number of kernel CVEs, not with rows per CVE. Stored rows and count rows share the key's `LIMIT`, so a key with a floor never returns more rows than it did before the rule, and no request can newly pass the 200,000-row limit because of it.
- **Package rows, assessed, not built.** The largest package keys on the copy: `Alpaquita:stream`/`linux-lts` 14,761 rows, `Alpaquita:25`/`linux-lts` 11,833, `Alpaquita:23`/`linux-lts` 9,448, `Azure Linux:3`/`kernel` 5,509; nothing else is over 5,000. Each of the 14,761 rows is its own advisory (one row per `BELL-CVE-*`), with 43 distinct `fixed` values. A filter that keeps `counts.not_affected` exact must return one row per advisory, which is the number of rows already read, so it would save nothing. It would also need each ecosystem's order (apk, dpkg, RPM) in SQL, which exists only in Go; a simpler SQL comparison is where a wrong "not affected" would come from. These keys grow by about one row per kernel CVE per release, so they are years from 50,000. OSV was unfinished on the copy (cursor at `CGA-`), so the Debian and Ubuntu kernel packages are not yet measured.
- **CNA rows, assessed, not built.** The copy holds no `Linux`/`Linux` CNA row: MITRE was unfinished (the highest CVE ID with CNA rows is CVE-2018-9999) and the kernel CNA began publishing in 2024. Nothing could be measured. The only key over the limit is `n/a`/`n/a` (92,131 rows), which no real item names. A version filter in SQL is not safe here: `versions` is JSON with free text, wildcard lines and `changes`, read by rules that exist only in Go (design section 4.3), and an entry the filter misreads could clear a version. Two options that do not read versions in SQL, both for after MITRE finishes and the key is measured: leave out rows whose every entry has `versionType` `git` (design 4.3 reads them as stating no version), returning a count per CVE as the CPE lookup does, because a CNA row with no NVD row still makes the advisory `cna_cannot_clear`; or raise the per-key limit for CNA rows, since the byte limit already bounds memory.

**Cost.**
- One Firefox item (about 35,000 rows): 0.26 s, 85 MiB allocated.
- 50 Firefox items at different versions: 4.3 to 8.4 s, 2.7 GiB allocated. The database read is shared, so the time is evaluation, about 54 MiB and 100 to 150 ms per item.
- 500 items over the 10 largest CPE products: 14.2 to 17.7 s, 11.4 GiB allocated, resident memory 180 to 200 MiB afterwards.
- A CPU profile of the 50-item request: `version.CheckNumeric` took 10.0 of 13.4 s of handler time. It runs `validateRange` and parses each bound with a regular expression and `math/big` on every comparison. `splitCPE` re-splits each row's CPE string for each item, about 1.7 s. Most of the rest of the process time was garbage collection of those allocations.
- Projection: with NVD complete, a valid 500-item request may pass the 30-second limit and answer 503. The go/no-go run re-measures this before any change is proposed.

**Data-side measurements on the copy** (`01-data.sql`, prepared in the Phase 2 session, and `03-phase4-extra.sql`). Provisional; repeated on the complete corpus:
- Keys over the 50,000-row limit: CPE `o:linux:linux_kernel` (82,061) and CNA `n/a`/`n/a` (92,131). No package key exceeds it; the largest is `Alpaquita:stream`/`linux-lts`, 14,761.
- Several fixes under one `introduced`, outside `Root:*` and `GIT`: 788 rows in 84 advisories and 30 packages, all `Alpine:v3.*`. None inside `Root:*` and `GIT`.
- Vulnerable CPE rows with no bounds: 3.81% of rows, on 26.71% of products.
- One CNA product and one NVD product, NVD analysed: of 173 CVEs where both sides are numeric, NVD reports a version at or past the CNA's highest clean bound in 32 (18.50%). The query returns rows, which settles that part of the Phase 2 verify-first note.
- CPE products with vulnerable rows under both `a:` and `o:`: 126 of 41,245, covering 7,837 CVEs. The largest are Cisco ASA, VMware ESXi and Xen.
- `SEMVER` package rows: 26,152, all `Bitnami`, in 7,917 records.
- CNA entries with a `*` lower bound and an upper bound: none yet (MITRE unfinished).
- CNA `package_key` values with whitespace: none (3 CVEs carry a `package_key` so far).
- Ubuntu Pro rows: none yet.
- Index use (M4) has to be read on the ingest database itself, because the copy's statistics start at zero.

---

## Execution recommendation

Subagent-driven development in a fresh session. The session that wrote this plan has consumed much of its context, and the plan is self-contained. Phases 1 and 3 are sequential because each task uses the previous task's types, so parallel agents would gain little. Task 3.5 warrants its own focused review, because a wrong "not affected" comes from there.
