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
**Overall:** Phase 1 shipped to `dev` (merge `45357f5`). Phase 2 (full ingest) is run by another session. Phase 3 (endpoint) is complete in [PR #218](https://github.com/scarson/CVErt-Ops/pull/218), open and unmerged until Phase 4 reports.

| Phase | Status | Ship SHA(s) | Notes |
|---|---|---|---|
| 1 — Data changes | ✅ Shipped 2026-11-10 | Merge `45357f5` on `dev`. Tasks: `2018ce4` (purl mapping), `c79cd32` (package key and indexes), `80c273b` (every CNA copy), `356bf6e` (NVD `caught_up`), `397a8c3` (`PLAN.md`). Review fixes: `ac5ad2b`, `7882fef`, `2899441`, `b741212` | Branch `claude/check-data-72f424`. [PR #213](https://github.com/scarson/CVErt-Ops/pull/213). Lint clean and full suite passed at `b741212` |
| 2 — Full ingest | ⬜ Not started | | Long-running; Phase 3 proceeds alongside it |
| 3 — Endpoint | 🚧 PR open 2026-11-10, awaiting Phase 4 | Task 3.1 `74b5011`, Task 3.2 `a9f86cf`, Task 3.3 `e7d2e87`, Task 3.4 `ae67ed3`, Task 3.5 `d251fe2`, review fixes `6e54c4d`, `7b5b880`, `8cf9c18`, `6618ae4`, `66a4091`; Task 3.6 `ac983d0`; Task 3.7 `cc2c772`; Task 3.8 `a6a97ce`, `4d31bda`; Task 3.9 `df55220`; Task 3.10 `6e8f968`; Task 3.11 `efd1df4`. Phase-end review fixes: round 1 `3781bec` to `3d8243a`, round 2 `b4a1e86` to `a4fa730`, round 3 `378ccbc` to `a72bd84`, round 4 `238ba4b`, `86d5578`. Head `5c4e025` | Branch `claude/check-endpoint-734a7a`. [PR #218](https://github.com/scarson/CVErt-Ops/pull/218) to `dev`, unmerged until Phase 4 reports. Lint clean and full suite passed at `5c4e025` |
| 4 — Measurement and merge | ⬜ Not started | | Sam decides the go/no-go |

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
- `TestCheckPackageIndexMatchesFoldedName` pins only the package index. Phase 3 should add the same pin tests for the CPE expression (`cpe_normalized COLLATE "C"`) and the CNA expressions (`left(lower(vendor), 256) COLLATE "C"`, and the same for `product`) when `internal/store/check.go` builds those predicates.

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

**Execution Status:** ⬜ NOT STARTED

Starts when Phase 1 is on `dev`. It runs for hours in the background, so Phase 3 proceeds at the same time. No code changes here.

**Step 1: Create a separate database.** Check out the Phase 1 merge commit in its own worktree, and run `bash docker/postgres-tls/generate-cert.sh` there, because the certificates are gitignored and Postgres will not start without them. `docker/compose.yml` fixes its container names, so a different project name alone does not isolate it. Make a copy of `.env` outside the repository with a free `POSTGRES_PORT`, and write a compose override file outside the repository that sets `container_name: cvert-check-ingest-postgres` on the Postgres service and gives it a volume of its own. Start only that service: `docker compose -p cvert-check-ingest -f docker/compose.yml -f <override> --env-file <copy> up -d <postgres service>`. Run `docker compose ... config` first, and confirm the container name, port and volume differ from the development stack. Sharing a volume with the development database is not acceptable.

**Step 2: Confirm credentials exist without printing them.** `NVD_API_KEY` (without it NVD is ten times slower) and the GHSA token the config names. If either is missing, ask Sam. Do not create accounts or keys.

**Step 3: Migrate and run.** In the copy of `.env`, change the port in both `DATABASE_URL` and `DATABASE_URL_MIGRATE` to the scratch port, because compose's `--env-file` does neither of these for host processes, and `DATABASE_URL_MIGRATE` takes precedence for migrations. In one PowerShell session, load the copy with the loop in `CLAUDE.md` §Dev Startup step 3, print the host and port of each URL (never the password) and confirm they are the scratch database, then run `go run ./cmd/cvert-ops migrate`, then `go run ./cmd/cvert-ops worker` in the background, with `FEED_SCHEDULER_ENABLED` on. Log to a file outside the repository.

**Step 4: Wait for the completion signals.** In `feed_sync_state`: `nvd` with `cursor_json->>'caught_up' = 'true'`, `ghsa` with non-empty `cursor_json->>'since'`, `osv` with `cursor_json->>'last_modified'` non-zero, and `mitre` having a recent `last_success_at`. If a feed fails repeatedly, find the root cause, and record it under Discoveries.

**Step 5: Record the data-side measurements** from design section 13 in this plan's Phase 4 notes: largest row counts per package and per CPE product, and how they compare to the 50,000 and 200,000 limits; how many CVEs have `package_key` with no row in `cve_affected_packages`; rows sharing the "several fixes under one `introduced`" shape outside `Root:*` and `GIT`; whether `cve_affected_packages_eco_pkg_idx` is still used (`pg_stat_user_indexes`); share of vulnerable CPE rows with no bounds; and, for CVEs with one CNA product and one NVD product and NVD analysis, how often NVD reports a version at or past the CNA's highest clean bound.

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
	CPEPrefixes    []CPEKey       // Lo "cpe:2.3:a:nodejs:node.js:", Hi "cpe:2.3:a:nodejs:node.js;"
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

-- CPE. lo is 'cpe:2.3:a:nodejs:node.js:'; hi is 'cpe:2.3:a:nodejs:node.js;'.
SELECT k.ord, m.cve_id, m.cpe_normalized, m.version_start_including, m.version_start_excluding,
       m.version_end_including, m.version_end_excluding, c.status
FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS k(lo, hi, ord)
CROSS JOIN LATERAL (
  SELECT q.* FROM cve_cpe_matches q
  WHERE q.cpe_normalized COLLATE "C" >= k.lo COLLATE "C"
    AND q.cpe_normalized COLLATE "C" <  k.hi COLLATE "C"
    AND q.vulnerable
  LIMIT $3
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

**Execution Status:** ⬜ NOT STARTED

Needs Phase 2's database and Phase 3's branch.

**Step 1: Point the Phase 3 build at the ingested database.** Load the same `.env` copy as Phase 2 Step 3, and confirm the URL host and port the same way, before running `go run ./cmd/cvert-ops serve` from the Phase 3 branch, with `METRICS_PORT` and `LISTEN_ADDR` set to free ports, because the Phase 2 worker still holds the default metrics port. Mint an API key through the application's own flow on that scratch database, for this measurement only.

**Step 2: Check the acceptance examples:** Node `24.22.0` returns CVE-2026-111497 with fixed `24.22.1`; `24.22.1` returns nothing for it; `php8.5` `8.5.4-0ubuntu1.4` in `Ubuntu:26.04:LTS` returns the PHP CVEs with fixed `8.5.4-0ubuntu1.5`, and shows `in_cisa_kev: true` on the `UBUNTU-CVE-*` records.

**Step 3: Measure the go/no-go in design section 13.** For Node, PHP, .NET, nginx, OpenSSL and PostgreSQL, at a current patched version and at one older version: item status, advisories by verdict and reason, and which CVEs hold each item at `cannot_evaluate`. Report the `cna_product_not_mapped` and `cna_name_uncertain` names, and whether they are worth table rows.

**Step 4: Report to Sam, and stop.** Sam decides whether the item roll-up stands. No threshold is set in advance. If it changes, that is a design change: amend the design, record it under Deviations, and add it to the Phase 3 pull request.

**Step 5: Merge** the Phase 3 pull request after Sam's decision.

**Step 6: Measure index write cost, then clean up.** On the scratch database only, set the NVD cursor back 7 days, run the worker until it catches up, and record CVEs merged per minute from its log. Drop the four indexes from Task 1.2 and repeat. Record both rates here. Then remove the Phase 2 containers and worktree, confirming first that they are this plan's.

---

## Execution recommendation

Subagent-driven development in a fresh session. The session that wrote this plan has consumed much of its context, and the plan is self-contained. Phases 1 and 3 are sequential because each task uses the previous task's types, so parallel agents would gain little. Task 3.5 warrants its own focused review, because a wrong "not affected" comes from there.
