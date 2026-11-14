# Product Conditions in Alert Rules (MATCH-2) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or superpowers:subagent-driven-development) to implement this plan task-by-task.

**Goal:** Alert rules can match CVEs by product (`affected.cpe_product`, from NVD vulnerable CPE rows and CNA vendor/product names), `affected.package` gains exact match (`eq`, `in`) correlated with the rule's ecosystem conditions on one package row, and a re-check signal re-evaluates a CVE whose CNA product names or NVD vulnerable flags change without moving `material_hash`.

**Architecture:** The DSL compiler emits each positive child-table condition as an uncorrelated CVE-ID set (`cves.cve_id IN (SELECT ...)`) that repeats the caller's candidate IDs inside every branch, so `CompiledRule.SQL` becomes `CompiledRule.Where(candidateIDs)`. Product names come from the version check's name table in `internal/check`, which exports its lookups and index expressions. Merge computes `match_inputs_hash` beside `material_hash`; the ingest handler and the batch scan treat a change in either as a reason to evaluate.

**Tech Stack:** Go 1.27, squirrel, lib/pq arrays, PostgreSQL 18 (btree skip scan), sqlc, golang-migrate, testcontainers-go.

**Approved design (authoritative; this plan implements it and does not restate its reasoning):** `dev/plans/2026-11-13-product-match-rules-design.md` — product field, package correlation, CVE-set query shape, re-check signal, validation messages, tests, measurements. Sam's two rulings are its section 15.1 (requirements restatement confirmed; re-check signal instead of a `material_hash` change). Its section 15.2 holds ten further decisions. Do not reopen any of them without asking Sam. Handoff: `dev/plans/2026-11-13-product-match-rules-handoff.md`.

**Governing pitfall:** `dev/implementation-pitfalls.md` DB-27 (rule predicates over child tables: uncorrelated sets with candidate IDs inside, `OR`-ed range predicates, `NOT EXISTS` for negatives, explain against one CVE and the whole corpus). DB-12 (dynamic `IN` lists overflow the 65,535-parameter limit; bind lists as one array) applies to Task 2.1.

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
  banner's recorded SHA reachable on the default branch, a 🚧 banner live
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
  workflow, record the squashed commit that landed on the default branch
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

Why this matters here: this plan runs over several sessions (code, a measurement gate on a kept database, and a decision gate with Sam), and the next session must be able to tell from this file alone which phases shipped and whether the measurement thresholds passed.

---

## Execution Status
<!-- Plan review and Overall are the only lines above the table. New content goes
     in the Deviations / Discoveries subsections below it — never above the table. -->

**Plan review:** ⚠️ TERMINATED-FOR-EXECUTION 2026-11-14 — 8 rounds (4 independent, all cross-model Codex cold reads), 2 verify-first flags annotated in place (Tasks 2.1 and 5.3)
**Overall:** ✅ All six phases complete on branch `claude/lucid-moser-fef966`; Phase 4 needed Sam's query-shape remedy (design section 17). PR to `dev`: [scarson/CVErt-Ops#244](https://github.com/scarson/CVErt-Ops/pull/244), merged 2026-11-14 as `6103f0d`.

| Phase | Status | Ship SHA(s) | Notes |
|---|---|---|---|
| 1 — Name table and value parser in `internal/check` | ✅ Shipped 2026-11-14 (branch; PR pending) | `cc883cd`, `3bf8255`, `43c878f` | Name table digest pinned at `f91e7929…a18b` |
| 2 — CVE-set form, `CompiledRule.Where`, package correlation | ✅ Shipped 2026-11-14 (branch; PR pending) | `7668072`, `c551369`, `f2f6f0e`, `1d0f6e6`, `daddbc2` | No existing integration test depended on uncorrelated matching |
| 3 — The `affected.cpe_product` field | ✅ Shipped 2026-11-14 (branch; PR pending) | `76359bc`, `71b4e9b`, `ead194c`, `fcde2c5`; review fix `d69081d` | Adversarial review found one branch defect (quadratic Validate cost), fixed |
| 4 — Measurements on the kept full ingest (gate) | ✅ Complete 2026-11-14: statement thresholds pass after Sam's remedy (`7ad8080`, `fe0e32f`, `9d58ee1`); M8 12 min accepted by Sam, follow-up separate | evidence `4d72221`, `bea8e03`, see next commit | Limit rule fails M5a, M5b, M5c, M8; M6 fails. `dev/plans/2026-11-13-product-match-rules-measurements.md` |
| 5 — Re-check signal | ✅ Shipped 2026-11-14 (branch; PR pending) | `fdbf47f`, `3232759`, `ce2b731` | Task 5.5 sparse page 3.7 s accepted by Sam; M8 2 min 4 s after PR 243 |
| 6 — PLAN.md, reviews, full suite, PR | ✅ Complete 2026-11-14 | `2a49cdb` … `4b65c2f` | Full suite passed at `4b65c2f`; PR [#244](https://github.com/scarson/CVErt-Ops/pull/244) merged as `6103f0d` |

### Deviations
- Phase 6 review fixes, decided by Claude under Sam's delegation (2026-11-14, "bias to action"): (1) a late-binding CVE ID rename or merge stamps `date_match_inputs_changed` so ID-keyed rules are re-checked by batch if realtime fails; (2) the never-matching ecosystem check runs only when every ecosystem value is valid (it was quadratic in a refused value's length); (3) validation reports one error per product condition and unmapped-product warnings only within the 50-product limit (a 1 MiB body produced up to 333,334 entries); (4) an `and` rule may hold at most 10 set conditions (measured: 10 sets 4.3 ms realtime, 20 sets 15.9 ms). Recorded in design section 17, PLAN.md §10.2 and the measurements file.
- Setup step 1: the work runs in the session's existing worktree, branch `claude/lucid-moser-fef966`, reset to `origin/dev` at `f593d74` before any change, instead of a new `claude/match2-impl` worktree. Same base, one writer.
- Task 1.2: the printable-ASCII refusal uses the message in the task's row 2 (`value must be printable ASCII with no spaces, as a CPE 2.3 name is`), which design section 8 does not list. `internal/check/input.go` `errProductValueNotASCII`.
- Task 1.2: `escapedAsCPERequires` does not call `firstUnescapedInvalid` (which would stop at the `*` and `?` the check must still accept). One iterator, `unescapedBytes`, does the escape walk, and `firstUnescapedInvalid`, `escapedAsCPERequires` and `hasUnescapedWildcard` read it. Check behaviour unchanged. `internal/check/input.go`.
- Task 1.1 also touched `internal/store/export_test.go` (removed aliases of the deleted helpers) and `internal/store/check_index_test.go` (the migration-pinning tests call the exported helpers). Task 1.3 also updated `TestKeysFor` and `TestKeysForItemUses` in `internal/check/keys_test.go`, which enumerate the Node names through their keys.
- Task 2.1 (`7668072`) also updated `TestCompile_EnumIn` (`internal/alert/dsl/dsl_test.go:~364`), which asserted the old placeholder count; the subject reads "..., strengthen tests".
- Task 2.2 (`c551369`): `ExecuteDSLQuery` keeps a nil guard (`if where := compiled.Where(nil); where != nil`) because `TestExecuteDSLQuery_NilSQL` passes a zero `CompiledRule`; `Where` returns nil for a rule with no predicates and no watchlist. `Where` treats any logic other than `or` as `and`; `Compile` still refuses unknown logic. SQL identity before and after was checked for six rule shapes with a throwaway capture test (not committed).
- Task 2.3 (`f2f6f0e`): `textOpsNoRegex` in `internal/alert/dsl/field.go` served only `affected.package` and was replaced by `packageOps`. Ecosystem lists are bound as written (only package-name lists are de-duplicated). A JSON `null` ecosystem list binds an empty array, keeping `in null` matching nothing and `not_in null` matching everything (`internal/alert/dsl/sets.go` `conditionValues`). Rewritten shape tests: `TestCompile_AffectedEcosystemEq`, `...EcosystemIn`, `...EcosystemMatchesExactOrSuffixed`, `...EcosystemEscapesLikeMetacharacters`.
- Task 2.3 meaning detail beyond correlation (design 4.1, ecosystems compared exactly): the `:%` release arm now applies only to bases that take a suffix, so `npm` no longer also matches a stored `npm:...`; canonical stored data has none.
- Task 2.4 (`1d0f6e6`): the never-matching check skips a rule whose `eq`/`in` ecosystem value fails to parse (that value already has its own error). A `neq` ecosystem condition does not suppress the no-ecosystem warning, per design section 8's wording.
- Task 2.5 (`daddbc2`): commit subject is `test(alert): add integration tests for package correlation and exact match`; cases run through both realtime and activation.
- Task 3.1 (`76359bc`): the unmapped-product warning quotes values with `"%s"`, not `%q`, so an escaped value such as `1und1:1\&1_online_storage` is shown as written (`internal/alert/dsl/validator.go:~50`). The create/PATCH symmetry test is renamed `TestAlertRule_ValidationErrorsSameOnCreateAndPatch` and made table-driven; its 51-product case is 51 one-value `eq nodejs:node.js` conditions (51 by Sam's per-condition ruling); the malformed `nodejs node.js` case returns the printable-ASCII message (`internal/api/alert_rules_test.go:~369`).
- Task 3.2 (`71b4e9b`): other-product vendor and product are lower-cased in Go before binding (no change for the all-lower-case table). `ProductSetSQL` with no values returns `FALSE`; `compileProducts` also refuses an empty list and any operator other than `eq`/`in`, so such a stored rule fails closed. The product branch in `Compile` runs before the regex branch, so a stored `regex` product condition is a compile error. `nameTableCPEs` in `sets_test.go` hard-codes the table's 10 CPE spellings (the digest test pins the table). Worst accepted rule with 5,000 candidate IDs: 1,590 args.
- Task 3.3 (`ead194c`): the every-path rule `{and: ecosystem eq npm, package eq fastify}` matches nothing in SeedCorpus (fastify is only a CNA product there); it is kept and pinned empty, and `{and: ecosystem eq npm, package eq jspdf}` (CVE-2026-31938) is added so a correlated package set is compared on a real match. The SeedCorpus, every-path and acceptance tests are not parallel (`SeedCorpus` and `GoldenPatch` call `t.Setenv`). Match sets are asserted exactly. Falsification probe of the full-vendor recheck: removing `lower(a.vendor) = ?` made both rows match; restored.
- Task 4.2: the harness writes its tables and inputs to a results directory (`KEPT_INGEST_RESULTS_DIR`, outside the repository) and the results file is assembled from them, rather than the harness writing `dev/plans/2026-11-13-product-match-rules-measurements.md` itself. M8's full activation is a separate file, `internal/alert/kept_ingest_activation_test.go`, because it writes (to the copy only; it refuses to run unless `KEPT_INGEST_COPY_CONFIRM` names the copy). A third test, `TestKeptIngestLimitSweep`, measures smaller limits and the full limit rule with parallel query off, as evidence for the gate decision. The kept ingest's TLS server is reached with `sslmode=prefer`.
- Phase 4 remedy (Sam, 2026-11-14): `or` rules match all their set-type conditions as one CVE set, and the evaluator's candidate statement runs without JIT. This changes design section 5.1's "one set per condition" for `or` rules only, and adds a JIT setting the design did not have. See the Phase 4 banner.
- Task 4.2 (M8): the copy was migrated to the committed head before the activation test with a binary built from a `git archive` export of `HEAD`, because the working tree was mid-edit at the time; the test's own migration step then found nothing to apply. The copy was analysed after its restore.

### Discoveries
- `/plan-check` (Task 6.2, 2026-11-14): every PLAN.md §5.3 and §10 requirement this branch adds or touches is met. Older requirements this branch does not touch, not fixed here: regex conditions compile without the `(?i)` default and run against a lower-cased description, so a pattern with an upper-case literal never matches (`internal/alert/dsl/compiler.go` regex PostFilter, `internal/alert/evaluator.go` `cveSummary`); an `or` rule with a regex condition behaves as `and` (`internal/alert/dsl/postfilter.go`); `fire_on_non_material_changes` (§10.4) is stored but never read by `internal/alert`; the zombie-activation sweeper marks the rule `error` without re-enqueueing (§10.3); no metric when a run hits the candidate cap; CVSS vector normalisation sorts metrics alphabetically where §5.3 says spec order (hash still stable); `cve_id` `eq`/`in` compare exactly; the regex selective-constraint check counts conditions that narrow nothing (`in_cisa_kev eq false`, conditions under `or`).
- Code review (2026-11-14), minor, not fixed here: `affected.package` `eq`/`in` values are folded in Go (`ecosystem.FoldPackageName`, `strings.ToLower`) while stored names are folded in SQL (`ecosystem.FoldedNameSQL`, PostgreSQL `lower()`); for a non-ASCII upper-case package name the two can differ under some database character types, so a rule might not match its own spelling. Package names are almost always ASCII. `internal/alert/dsl/sets.go` (package match).
- Code review (2026-11-14), minor, not fixed here: the unmapped-product warning (design section 8's text) names only the spelling with `_` read as a space, but the value's own spelling with `_` (and mixed pairs) also match a CNA row. Wording fix belongs in the design first. `internal/alert/dsl/validator.go` (unmapped warning).
- Task 6.1 (2026-11-14): no CLI or MCP code exists on this branch (the only hits for `affected.package` outside `internal/alert` and `internal/api` are the AI prompt notes Task 3.4 updated). When the CLI/MCP design (`dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md`) is built, it must carry `affected.cpe_product`, `affected.package` `eq`/`in`, the limits (50 product values, 100 conditions, 10 set conditions per `and` rule) and the never-matching ecosystem error.
- Security review (2026-11-14), not fixed here, follow-up: saved searches and AI searches (`store.ExecuteDSLQuery`) run rule SQL with the server defaults (JIT and parallel query on), unlike the evaluator; a large `or` rule run as a saved search can be slow or hit the 64 MB shared-memory limit. Each statement is bounded by the statement timeout. Fix by running `ExecuteDSLQuery` in a read-only transaction with the evaluator's settings.
- Found by Task 5.6's after-group review (2026-11-14), older than this branch, not fixed here: after a late-binding CVE ID rename (`migrateCVEPKRename`), the renamed row keeps its old change dates unless an alert moved with it, so if realtime evaluation fails on the promoting merge, a rule bound to a watchlist that lists the new CVE ID is not evaluated against it by the batch path. Needs Sam's decision.
- Found while planning (2026-11-14): design section 12's line "Each refusal the rule adds to the check's parser (section 3.1) is also refused by the check in a full CPE" contradicts design section 3.1, which says the check accepts unescaped `*` and `?`. Task 1.2 tests section 3.1's invariant (every value a rule accepts, the check accepts). Flagged only; the design text is unchanged.
- Found while planning (2026-11-14): design section 8's message table has no message for the printable-ASCII refusal that section 3.1 requires; Task 1.2 adds one. Record it under Deviations when Task 1.2 ships. (Recorded.)
- Found while executing (2026-11-14): the host's `golangci-lint` (v2.10.1, built with Go 1.26) refuses to load `.golangci.yml` under Go 1.27. Lint runs with the CI pin instead: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run --allow-parallel-runners ./cmd/... ./internal/... ./migrations/...`.
- Verified 2026-11-14 (verify-first, Task 2.1): `internal/alert/dsl/dsl_test.go` is package `dsl_test` with no `TestMain` and no database, so the shape and parameter-count tests belong there; `internal/store/main_test.go` calls `testutil.Run`, so the `null`/empty-list cases run in `internal/store/dsl_executor_test.go`. `json.Unmarshal` of `null` into `[]string` gives nil with no error, so the nil-to-empty normalisation is required.
- Found by the after-Phase-3 review (2026-11-14), older than this branch, not fixed here: for a stored rule holding an operator `Validate` refuses, `Compile` builds wrong SQL instead of failing closed. `severity gte "high"` or `contains` compiles to `lower(cves.severity) <> ?` (`internal/alert/dsl/compiler.go` `setSQL`/enum path treats any other operator as `neq`); `in_cisa_kev neq true` compiles to `= ?` (bool path ignores the operator); `fts_query eq` compiles to an FTS match. Suspected, unconfirmed: `cvss_v3_score gt null` validates and compiles to `> 0`. Only reachable through a rule edited in the database; PLAN.md §10.5 expects fail-closed.
- Kept ingest pre-flight (Task 4.1, 2026-11-14): PostgreSQL 18.4, 2,628,861 CVEs, migrations at 61 (62 `alert_events_feed_seq` not applied; the measurements do not read `alert_events`); all three check indexes match `check.CPEIndexExpr`, `check.CNANameIndexExpr` and `ecosystem.FoldedNameSQL`.
- Production shared memory (2026-11-14): no compose file sets `shm_size` for Postgres (`docker/compose.yml`, `docker/compose.prod.yml`), so a deployed Postgres has Docker's default 64 MB `/dev/shm`, the same as the kept ingest container. The limit rule's dry-run and batch statements failed there with `could not resize shared memory segment ... No space left on device` (a parallel hash), so they would fail the same way in a default deployment.
- Fixed after MATCH-2 (2026-11-14, branch `fix/alert-dsl-predating-bugs`): regex conditions now ignore case by default and match the description as stored; an `or` rule combining regex with other conditions is refused at save and fails closed when stored; `Compile` refuses operators a field does not take; and a JSON `null` single value is refused (it was confirmed: `cvss_v3_score gt null` compiled to `> 0`). Entries in `dev/implementation-log/` dated 2026-11-14T0746Z, T0750Z and T0754Z. The other older findings above remain open.
- Fixed after MATCH-2 (2026-11-14, branch `claude/match2-followups`), the remaining findings above, one log entry each in `dev/implementation-log/`:
  - Candidate cap: `cvertops_alert_candidate_cap_exceeded_total` and a warning log (T0744Z). Only a dry-run can exceed the cap; every evaluation path passes at most 5,000 candidate IDs per statement.
  - CVSS normalisation: PLAN.md §5.3, CLAUDE.md and AGENTS.md now describe the metric sort the hash uses (T0750Z). The code is unchanged: stored vectors keep the source's order, and switching to spec order would change every `material_hash` once and re-fire matching rules for no change in behaviour.
  - Zombie activations (T0753Z): the worker pool's stale-job recovery re-queues a stuck job until `max_attempts`, then marks it `dead` (it re-queued forever on every queue, and reclaimed jobs at 12 minutes, before the 15-minute sweeper could see them); the sweeper moves a rule left `activating` with no pending or running job to `error`.
  - Package names: `eq`/`in` values are bound as written and folded in the database by the index expression's rule, and substring patterns keep their case for `ILIKE` (T0805Z). EXPLAINed on the kept ingest; DB-27 records it.
  - Regex rules: only conditions that narrow the candidates count toward the guardrail (T0809Z); conditions under `or` were settled by the `or` refusal above.
  - Unmapped-product warning: design section 8 first, then the message lists every CNA spelling of each part (T0810Z).
  - `cve_id`: values shaped like a CVE ID compare upper case (T0813Z).
- Fixed after MATCH-2 (2026-11-14, branch `claude/postgres-shm-size`): the Postgres service in `docker/compose.yml` sets `shm_size: 256mb`, which the production overlay inherits, and `docker/compose_test.go` checks it in both stacks (T0858Z). Rule statements already run with parallel query off; the larger `/dev/shm` covers the queries that still run in parallel (search, facets, reports). `docs/deployment/production.md` explains the setting for operators who run their own Postgres container.
  - `fire_on_non_material_changes` (§10.4), stored but never read: removed on Sam's decision (2026-11-14), from the API, the `alert_rules` table (migration 000064) and PLAN.md §10.4. Reasons in `dev/plans/2026-11-14-remove-fire-on-non-material-changes-design.md`; log entry T0835Z.

---

## Read before starting

Every executor (and every subagent) reads these first. They are short or sectioned; read the named sections, not the whole file, unless told otherwise.

1. The design: `dev/plans/2026-11-13-product-match-rules-design.md` sections 3 to 8, 12, 13 and 16 in full. Each task below names the design section it implements; the design is the source of truth for messages, SQL shapes and test cases.
2. `dev/implementation-pitfalls.md` DB-27 (query shapes) and DB-12 (array binding, including its squirrel note).
3. `dev/testing-pitfalls.md` §2 (negative property testing), §4 (validation symmetry: create and PATCH return the same errors), §7 (store conventions), and the `SeedCorpus` guidance under §9.
4. Project `CLAUDE.md`: TDD, ABOUTME headers on every new Go file, one `dev/implementation-log/` entry per commit (in the same commit; naming rules in `dev/implementation-log/README.md`), never raw-SQL-seed CVEs (use `testutil.SeedCorpus` or `merge.Ingest` with a `feed.CanonicalPatch`).

### Guardrails for every task

- **Privacy:** the repository is public. Never quote, name or commit the private homelab requirements document, its host names, or local user paths. Refer to the requirement as "MATCH-2" and to the design's section 1.
- **Decisions are closed:** design sections 15.1 and 15.2. If code reality contradicts one, stop and ask Sam; do not pick a different behaviour.
- **SQL values are always bind parameters.** Ranges, prefixes, names, folded names and LIKE patterns are built in Go and passed as arguments. Only fixed SQL fragments and column expressions returned by `internal/check`/`internal/ecosystem` helpers are concatenated.
- **Lint:** `golangci-lint run --allow-parallel-runners ./...` before each commit (the lock is host-wide; exit 3 with "parallel golangci-lint is running" is not a lint result).
- **Test scope:** run the package(s) a task changes. Docker-backed packages (`internal/alert`, `internal/store`, `internal/merge`, `internal/ingest`) need Docker Desktop running; if it is not, that is a hard blocker (stop and report), never "compiles, tests not run". Full suite only at Task 6.4.
- **Assertion rigor:** if a test assertion races, flakes, or fails nondeterministically, the fix is deterministic synchronization (an awaitable fence, a channel, an explicit DB read after the write commits) — NOT assertion removal or weakening. If synchronization cannot make the assertion pass reliably, STOP and raise it to the dispatching agent. Do not ship a weaker test. Weakened assertions rationalized as "CI stability fixes" are the exact pattern this rule prevents. Prefer mechanism assertions (an event row exists at this hash; `date_modified_canonical` unchanged) over symptom assertions (a count went up). Commit subjects that touch test assertions say what happened to them ("add", "strengthen", "preserve", or "weaken" with the reason).

### TDD blocks (apply to every task)

```
BEFORE starting work:
1. Invoke /superpowers:test-driven-development
2. Read dev/testing-pitfalls.md (sections named in "Read before starting")
Follow TDD: write failing test → implement → verify green. Cover the
error paths and edge cases as you write the tests — that is part of
writing them, not a separate audit afterwards.
```

```
BEFORE marking this task complete:
1. Review tests against dev/testing-pitfalls.md
2. Run tests and confirm green
```

(This project keeps its pitfalls documents at `dev/implementation-pitfalls.md` and `dev/testing-pitfalls.md`, not under `docs/pitfalls/`.)

---

## Setup (before Phase 1)

1. Create the implementation worktree from local `dev` (project rule: worktree branch → `dev` → `main`):
   ```bash
   git fetch origin dev:dev
   git worktree add .claude/worktrees/match2-impl -b claude/match2-impl dev
   ```
   `git fetch origin dev:dev` fast-forwards local `dev` and refuses if `dev` is checked out elsewhere or has diverged; in that case stop and ask Sam rather than forcing it. Confirm the branch contains this plan's merge (`git log --oneline -1 -- dev/plans/2026-11-13-product-match-rules-plan.md`).
2. Copy the SPA build so `internal/api` and `cmd/cvert-ops` compile: from the worktree root, `cp -r ../../../web/dist web/dist`. If the main checkout has none, run `cd web && npm run build` there first.
3. Baseline: `go build ./...`, then `go test ./internal/check/... ./internal/alert/dsl/... -count=1`. Record any pre-existing failure under Discoveries before touching code.
4. Check `migrations/` on `origin/dev` for the highest number. This plan assumes the next free number is `000063`; if another branch has taken it, use the next free number everywhere this plan says `000063`.

---

## Phase 1 — Name table and value parser in `internal/check`

**Execution Status:** ✅ SHIPPED 2026-11-14 on branch `claude/lucid-moser-fef966` — `cc883cd` (Task 1.1), `3bf8255` (Task 1.2), `43c878f` (Task 1.3). After-phase review: one round, no material findings.

Design section 3.1 (value rules), 3.4 (shared name table), 5.1 (ASCII boundary test), 12 (unit tests). One logical commit in design section 16's order; tasks may commit separately in this order.

### Task 1.1: Move the index-expression helpers into `internal/check` and export the lookups the compiler needs

**Why:** the DSL compiler cannot import `internal/store` (which imports `internal/alert/dsl`), and an expression that drifts from the index definition silently falls back to a sequential scan (design 3.4).

**Files:**
- Modify: `internal/check/keys.go` (export `cnaNameKey` as `CNANameKeyFor`; add `CPEIndexExpr`, `CNANameIndexExpr`)
- Modify: `internal/check/names.go` (export `OtherProductsFor`, `IsOtherProduct`)
- Modify: `internal/check/keys.go:150`, `internal/check/evaluate.go:237,254`, `internal/check/keys_test.go`, `internal/check/names_test.go` (callers of the renamed functions)
- Modify: `internal/store/check.go:38-45,104-109` (delete the two local helpers; call `check.CPEIndexExpr` / `check.CNANameIndexExpr` at every use, lines 158-225)
- Test: `internal/check/keys_test.go`

**Exact changes:**

```go
// internal/check/keys.go

// CPEIndexExpr is the expression cve_cpe_matches_check_idx indexes, on column:
// its first CPEKeyRunes characters, so a CPE of any length fits a btree row.
// The C collation lets a range on a CPE prefix use the index whatever the
// database collation. A statement ranges on it with a CPEKey's Lo and Hi and
// rechecks the key's whole Prefix with starts_with.
func CPEIndexExpr(column string) string {
	return fmt.Sprintf(`left(%s, %d) COLLATE "C"`, column, CPEKeyRunes)
}

// CNANameIndexExpr is one of the expressions cve_cna_affected_check_idx
// indexes, on column (vendor or product): its first cnaNameRunes characters,
// lower-cased, which CNANameKeyFor cuts its names to match.
func CNANameIndexExpr(column string) string {
	return fmt.Sprintf(`left(lower(%s), %d) COLLATE "C"`, column, cnaNameRunes)
}
```

Move the existing doc comments from `internal/store/check.go` with the functions (keep their content; do not delete comments). `cnaNameIndexExpr` today hard-codes `256`; the moved version uses `cnaNameRunes` (also 256), so the emitted text is unchanged — assert that in the test.

```go
// internal/check/names.go

// OtherProductsFor returns the CNA products that a name of p would find but
// that are other products (otherProducts), or nil.
func OtherProductsFor(p ProductRef) []CNAName { return otherProducts[p.Vendor+":"+p.Product] }
```

Rename `isOtherProduct` to `IsOtherProduct` (exported, same doc comment), and `cnaNameKey` to `CNANameKeyFor`. Keep `keysWithUses` reading `otherProducts` through `OtherProductsFor`.

Export only these. The design's section 3.4 list (which also names `cutRunes`, `nextPrefix`, `cnaNameRunes`) is the upper bound; the compiler needs only the key builders' outputs. Do NOT export anything else.

**Tests (write first):**
- `TestIndexExpressions` in `internal/check/keys_test.go`: `CPEIndexExpr("m.cpe_normalized") == "left(m.cpe_normalized, 512) COLLATE \"C\""` and `CNANameIndexExpr("a.vendor") == "left(lower(a.vendor), 256) COLLATE \"C\""` — the exact strings `internal/store/check.go` emits today, so the store statements are byte-for-byte unchanged.
- Existing `internal/check` and `internal/store` check tests must pass unchanged.

**Run:** `go test ./internal/check/... -count=1` then `go test ./internal/store/... -count=1 -run 'Check'` (Docker).

**Commit:** `refactor(check): export name lookups and index expressions for rule matching` with its implementation-log entry.

### Task 1.2: The rule's product value parser

**Files:**
- Modify: `internal/check/input.go` (add `ParseProductValue`, `firstUnescapedInvalid`; make `escapedAsCPERequires` call the latter)
- Test: `internal/check/input_test.go`

**Behaviour (design 3.1 and the message table in design section 8):** `ParseProductValue(raw string) (ProductRef, error)` returns `ProductRef{Vendor, Product}` with `Part` empty, lower-cased, redundant escapes dropped (`dropRedundantEscapes`). Checks run in this order; the first failure returns an error whose `Error()` is the exact message:

| # | Check | Message |
|---|---|---|
| 1 | more than 255 characters (`utf8.RuneCountInString`) | `value must not exceed 255 characters` |
| 2 | any character outside `0x21`–`0x7e` (before lower-casing) | `value must be printable ASCII with no spaces, as a CPE 2.3 name is` |
| 3 | after `strings.ToLower` and `splitCPE`: not exactly 2 parts, or a part empty | `value must be "vendor:product", the vendor and product of a CPE 2.3 name, for example "nodejs:node.js"` |
| 4 | after `dropRedundantEscapes`: a part is `*` or `-`, or holds an unescaped `*` or `?` | `vendor and product must be literal names, not "*", "-" or a pattern with "*" or "?"` |
| 5 | a part ends in an unescaped backslash | `vendor and product must not end in an unescaped backslash` |
| 6 | first unescaped character that CPE 2.3 requires escaped (not a letter, digit, `.`, `-`, `_`) | `character "+" must be escaped with a backslash, as NVD writes CPE names (for example "notepad\+\+")`, with the offending character in place of `+` |

Row 2's message is not in the design's table: the design requires the printable-ASCII refusal (section 3.1) but gives it no message. This message fills that gap; record it under Deviations when shipped.

Implement row 6 with `firstUnescapedInvalid(v string) (byte, bool)` that walks like `escapedAsCPERequires` and returns the first unescaped byte outside `[a-z0-9._-]`; row 4's `*`/`?` check is a separate walk (unescaped `*` or `?` anywhere). Then make `escapedAsCPERequires` (used by `parseCPE`) keep its current behaviour — it still accepts unescaped `*` and `?` — so the check endpoint's behaviour does not change.

**Tests (table-driven, write first):**
- Accepted: `nodejs:node.js` → `{Vendor:"nodejs", Product:"node.js"}`; `NodeJS:Node.JS` → lower-cased; `nodejs:node\.js` → `node.js` (escape dropped); `1und1:1\&1_online_storage` → kept as written; `microsoft:.net`; `f5:nginx_open_source`; `notepad-plus-plus:notepad\+\+`; a 255-character value.
- Refused, one per message row, asserting the exact message: 256 characters; KELVIN SIGN, built as `"nodejs:" + string(rune(0x212A)) + "node"` so the source stays ASCII (row 2); `nodejs node.js` (row 2, space); `nodejs`; `a:b:c`; `:node.js`; `nodejs:`; `*:node.js`; `nodejs:-`; `nodejs:node*`; `nodejs:no?de`; `nodejs:\-` (becomes `-` after escape drop → row 4); `nodejs:node.js\` (row 5); `notepad-plus-plus:notepad++` (row 6 naming `+`).
- **Check-endpoint invariant (design 3.1):** for every accepted value above, `ParseItem(0, RawItem{CPE: "cpe:2.3:a:" + v + ":1.0:*:*:*:*:*:*:*"})` returns an item with no `Error`. For the rule's own refusals, pin what the check does: trailing backslash → the check refuses (`invalid_cpe`); unescaped `*` or `?` inside a component → the check accepts. Design section 12's line "Each refusal the rule adds ... is also refused by the check" contradicts section 3.1 for `*` and `?`; section 3.1 (rule-accepts implies check-accepts) is the invariant tested. Record this under Discoveries as a design wording defect.

**Run:** `go test ./internal/check/... -count=1 -run 'ProductValue|ParseItem'`.

**Commit:** `feat(check): parse vendor:product values for alert rules` + log entry.

### Task 1.3: Two Node names, the ASCII word boundary, and the table digest

**Files:**
- Modify: `internal/check/names.go` (Node row `Names`; `IsOtherProduct` boundary; `nameTableDigest`)
- Test: `internal/check/names_test.go`

**Changes:**
1. Node row (`names.go:49-54`) `Names` becomes `{nodejs, node}, {nodejs, nodejs}, {node.js, node.js}, {the node.js project, node.js}` (design 3.4; all lower case).
2. `IsOtherProduct`: replace `!unicode.IsLetter(rest[0]) && !unicode.IsDigit(rest[0])` with an ASCII test: the rune after the prefix is not in `a`–`z` or `0`–`9` (product is already lower-cased). Remove the `unicode` import if unused. Update the doc comment: a prefix matches up to a word boundary, and any character other than an ASCII letter or digit is a boundary.
3. Add `nameTableDigest() string`: `sha256` hex of `json.Marshal(struct{Table []cnaMapping; Other map[string][]CNAName}{cnaTable, otherProducts})` (`json.Marshal` sorts map keys, so the digest is deterministic).

**Tests (write first):**
- `NamesFor(ProductRef{Vendor:"nodejs", Product:"node.js"})` lists exactly these five names (order as `NamesFor` produces them, assert as a set): `nodejs/node.js`, `nodejs/nodejs`, `nodejs/node`, `node.js/node.js`, `the node.js project/node.js`. (Five names × 4 parameters plus 6 CPE ranges × 3 is the 38 parameters design 3.2 counts; Phase 3 asserts that count.)
- `IsOtherProduct(dotNetOthers, "Microsoft", ".NET Framework 4.8")` true; `".NET FrameworkExtensions"` false; `".NET Framework"` true (nothing after); `".NET Frameworké"` true (non-ASCII letter is now a boundary); `".NET Framework9"` false.
- `TestNameTableDigest`: `nameTableDigest()` equals a pinned hex constant (compute it once after change 1, paste it). Failure message, verbatim in the test:
  `the CNA name table changed. Before updating this digest, build the re-check step in dev/plans/2026-11-13-product-match-rules-design.md section 3.4 (re-evaluate rules with affected.cpe_product conditions over CVEs under changed table entries), or confirm with Sam that the edit changes no stored match.`
  Add a second test that mutates a copy (append a name to a cloned table, change a fragment, add an other product) through a helper `digestOf(table, other)` that `nameTableDigest` also calls, and asserts each mutation changes the digest — so the pin cannot be satisfied by a digest that ignores a field.
- Existing name tests in `names_test.go` keep passing; update only those that enumerate the Node row's names.

**Run:** `go test ./internal/check/... -count=1`, then `go test ./internal/store/... -count=1 -run 'Check'` and `go test ./internal/api/... -count=1 -run 'Check'` (the version check endpoint's stored answers must not change; design 3.4 and 5.1 say no stored answer changes).

**Commit:** `feat(check): add Node.js CNA spellings, ASCII product boundary, name table digest` + log entry.

**Seam (version check endpoint):** these two changes alter the version check design's section 4.5 table (`dev/plans/2026-11-08-version-check-endpoint-design.md`). Task 6.1 adds the amendment line there.

### After Phase 1

Review the batch once, from a perspective the individual tasks did not apply (here: does every caller of the renamed check functions still compile and behave identically for the version check endpoint?). Run further rounds only while the previous round produced material findings; stop when one produces none. A round run to reach a count, after findings have stopped, manufactures them — and a manufactured finding is the same defect as a suppressed one.

---

## Phase 2 — CVE-set form, `CompiledRule.Where`, package correlation

**Execution Status:** ✅ SHIPPED 2026-11-14 on branch `claude/lucid-moser-fef966` — `7668072` (2.1), `c551369` (2.2), `f2f6f0e` (2.3), `1d0f6e6` (2.4), `daddbc2` (2.5). Pitfall check on 2.2: no findings. After-group review: one round, no material findings.

Design sections 3.2 (array binding, 100-condition limit), 4 (exact match and correlation), 5.1 (package SQL), 5.2 (compiler contract), 8 (validation), 12 (tests). Tasks are sequential; all touch `internal/alert/dsl`.

### Task 2.1: Bind every `in`/`not_in` list as one array parameter

**Why:** DB-12. `setSQL` uses `sq.Eq{expr: vals}`, which squirrel renders as `IN (?, ?, …)`, one parameter per value.

**Files:** Modify `internal/alert/dsl/compiler.go:255-274`; Test `internal/alert/dsl/dsl_test.go` (SQL shape and parameter counts only: `TestCompile_EnumNotIn` at line ~837 and the `NOT IN` assertion near line 1376; this package has no `TestMain` and no database); Test `internal/store/dsl_executor_test.go` (the database-backed `null`/empty-list cases below; `internal/store/main_test.go` already calls `testutil.Run`).
> **Verify-first (plan review round 8, unverified repair):** the split of Task 2.1's tests between the two files was set in the last review wave and was not re-reviewed. Confirm each listed test lands in a package that can run it.

**Change:**
```go
if op == "in" {
	return sq.Expr(sqlExpr+" = ANY(?)", pq.Array(vals)), nil
}
return sq.Expr(sqlExpr+" <> ALL(?)", pq.Array(vals)), nil
```
`sqlExpr` is a registry constant (`cves.cve_id`, `lower(cves.severity)`), never user input. Before binding, replace a nil `vals` with `[]string{}`: the validator accepts JSON `null` for a list (it unmarshals into a nil slice), and `pq.Array(nil)` binds SQL NULL, which would turn `not_in: null` from "matches everything" (squirrel's `(1=1)` for an empty `NotEq`) into "matches nothing" (`<> ALL(NULL)` is NULL). With that, NULL behaviour is unchanged: `NULL <> ALL(arr)` is NULL as `NULL NOT IN (...)` was; an empty array gives false for `= ANY` and true for `<> ALL`, as squirrel's `(1=0)`/`(1=1)` did. Every list Phase 2 and 3 bind with `pq.Array` gets the same nil-to-empty normalisation.

**Tests:**
- Update `TestCompile_EnumNotIn`: SQL contains `lower(cves.severity) <> ALL(`; exactly one arg, a `pq.StringArray`-compatible value holding `["low","none"]`. Commit subject says "strengthen" (the old test asserted placeholder count; the new one asserts the shape and the bound values).
- In `internal/store/dsl_executor_test.go`, through `store.ExecuteDSLQuery` on a `SeedCorpus` database: `severity not_in null` and `severity not_in []` each return every CVE that is not rejected or withdrawn, including CVEs whose severity is NULL; `severity in null` and `severity in []` return none.
- Add `TestCompile_SetListIsOneParameter`: `cve_id in` with 70,000 generated IDs compiles to SQL with exactly one `$`/`?` placeholder and one arg.
- Integration (existing `internal/store` DSL executor tests and `internal/alert` evaluator tests using `severity in`): must pass unchanged. Run `go test ./internal/store/... -count=1 -run DSL` and `go test ./internal/alert/... -count=1 -run 'Evaluator'`.

**Commit:** `fix(dsl): bind in and not_in lists as one array parameter` + log entry.

### Task 2.2: `CompiledRule.Where(candidateIDs)` with no change in SQL meaning

**Why:** design 5.2: the set form depends on the caller's candidate IDs. This task changes the contract only; Task 2.3 changes the shapes.

**Files:**
- Modify: `internal/alert/dsl/types.go` (replace `SQL sq.Sqlizer` with unexported `predicates []predicate`, `watchlist sq.Sqlizer`; add `Where`)
- Modify: `internal/alert/dsl/compiler.go:21-113` (Compile builds predicates)
- Modify: `internal/alert/evaluator.go:600-626` (extract `candidateQuery`; use `Where`)
- Modify: `internal/store/dsl_executor.go:134-137`
- Modify: `internal/alert/dsl/dsl_test.go:334-341` (`sqlOf` calls `c.Where(nil)`), and lines ~614, ~733
- Test: `internal/alert/dsl/dsl_test.go`

**Contract:**
```go
// predicate builds one compiled condition's SQL. candidateIDs limits a CVE-set
// condition to those IDs; nil or empty means the whole corpus.
type predicate func(candidateIDs []string) sq.Sqlizer

// Where returns the rule's WHERE predicate (no FROM, no LIMIT). A set condition
// repeats candidateIDs inside each of its branches (pitfall DB-27); callers that
// have candidate IDs also filter cves.cve_id on them themselves.
func (c *CompiledRule) Where(candidateIDs []string) sq.Sqlizer
```
`Where` combines `predicates` by `Logic` exactly as `Compile` combines `sqlParts` today (lines 59-91): `and` → `sq.And{parts..., watchlist?}`; `or` → `sq.Or{parts}` wrapped in `sq.And{or, watchlist}` when a watchlist exists; no predicates → the watchlist expression (Compile already refuses no predicates and no watchlist). A `CompiledRule` is cached and shared across goroutines (`RuleCache`), so predicates MUST be pure closures over values computed in `Compile`; they must not mutate captured slices.

In this task every existing condition becomes `func(_ []string) sq.Sqlizer { return s }` around today's Sqlizer, so the SQL text is unchanged.

**Callers (all must change; no other callers exist — confirmed with `grep -rn "\.SQL\b" --include=*.go internal`):**
- `evaluator.queryCandidates`: extract the statement builder into `func candidateQuery(compiled *dsl.CompiledRule, candidateIDs []string) (string, []any, error)` (same SQL as today, using `compiled.Where(candidateIDs)`), and have `queryCandidates` call it. Phase 4's measurement harness reuses `candidateQuery`, so the measured statement is the production statement.
- `store.ExecuteDSLQuery`: `sb = sb.Where(compiled.Where(nil))` (saved searches and AI search have no candidate IDs; design 5.2 table).
- `internal/api/ai.go` and `internal/api/saved_searches.go` call `Compile` and `ExecuteDSLQuery` only; they need no change. Confirm they compile.

**Tests:**
- Existing `dsl_test.go` compile tests pass through `sqlOf` → `Where(nil)` with identical SQL and args.
- New `TestWhere_IsDeterministicAcrossCalls`: call `Where(nil)` and `Where([]string{"CVE-1"})` twice each on one CompiledRule; `ToSql()` results are equal per input (purity of cached rules).

**Pitfall gate:** this commit touches the evaluator. Run `/pitfall-check` on `internal/alert/evaluator.go`, `internal/alert/dsl/*.go` and `internal/store/dsl_executor.go` before committing; fix or record every finding (never drop one).

**Run:** `go test ./internal/alert/dsl/... -count=1`, `go test ./internal/alert/... -count=1`, `go test ./internal/store/... -count=1 -run DSL`, `go test ./internal/api/... -count=1 -run 'SavedSearch|AI|AlertRule'`.

**Commit:** `refactor(dsl): build a rule's WHERE predicate per candidate list` + log entry.

### Task 2.3: Package and ecosystem conditions as CVE-ID sets, with correlation and exact match

**Files:**
- Create: `internal/alert/dsl/sets.go` (ABOUTME header: "Builds the CVE-ID set predicates for child-table conditions" / "Each set repeats the caller's candidate IDs inside its branches (pitfall DB-27)")
- Modify: `internal/alert/dsl/compiler.go` (replace `affectedSQL`, `affectedEcosystemSQL`, `affectedPackageSQL`; add the `and`-rule grouping pass)
- Modify: `internal/alert/dsl/field.go:53` (`affected.package` ops become `contains`, `starts_with`, `ends_with`, `eq`, `in`)
- Modify: `internal/ecosystem/ecosystem.go` (export `TakesSuffix(base string) bool` reading `takesSuffix`)
- Test: `internal/alert/dsl/dsl_test.go` (or a new `internal/alert/dsl/sets_test.go`), `internal/ecosystem/ecosystem_test.go`

**Compile rules for an `and` rule (design 4.2):**
1. Collect the rule's `affected.ecosystem` conditions with `eq`/`in` ("correlated ecosystem conditions") and its `affected.package` conditions.
2. Each package condition compiles to one package set holding its own predicate plus one ecosystem line per correlated ecosystem condition. It is emitted at the package condition's position.
3. If the rule has at least one package condition, the correlated ecosystem conditions emit nothing on their own.
4. If it has none, each `eq`/`in` ecosystem condition compiles to its own ecosystem set.
5. `neq`/`not_in` ecosystem conditions always compile to `NOT EXISTS` (correlated; DB-27).

Under `or`, every condition compiles on its own: a package condition is a package set with no ecosystem lines; an `eq`/`in` ecosystem condition is an ecosystem set.

**SQL (bind parameters shown as `?`; the candidate line appears only when `len(candidateIDs) > 0`):**

Package set:
```sql
cves.cve_id IN (
    SELECT cap.cve_id FROM cve_affected_packages cap
    WHERE cap.cve_id = ANY(?)                                   -- candidate line
      AND (cap.ecosystem = ANY(?) OR cap.ecosystem LIKE ANY(?)) -- one per correlated ecosystem condition; LIKE arm only when needed
      AND <package predicate>
)
```
Ecosystem set: the same with no package predicate and exactly one ecosystem line.

Ecosystem line: `$ecos` holds the condition's values exactly as written (canonical names; `ecosystem.Valid` already enforces this in the validator). The `LIKE ANY` arm is present only when at least one value's base (`strings.Cut(v, ":")` before the first colon) satisfies `ecosystem.TakesSuffix`; `$releases` then holds each such value `escapeLike`d plus `:%`. So `Debian` covers `Debian:13`, `Ubuntu:22.04` covers `Ubuntu:22.04:LTS`, and `npm` alone is `cap.ecosystem = ANY(?)`, which `cve_affected_packages_check_idx` serves.

Negative ecosystem condition:
```sql
NOT EXISTS (SELECT 1 FROM cve_affected_packages cap
            WHERE cap.cve_id = cves.cve_id
              AND (cap.ecosystem = ANY(?) [OR cap.ecosystem LIKE ANY(?)]))
```
Ecosystems are compared exactly everywhere (design 15.2, "Ecosystems compared exactly"); `WatchlistPackageMatchSQL` keeps `lower()` (handoff Seams: deliberate difference, do not touch it).

Package predicate:

| Operator | Predicate |
|---|---|
| `eq`, `in` | `<folded> = ANY(?)` where `<folded>` is `ecosystem.FoldedNameSQL("cap.ecosystem", "cap.package_name")` (the `cve_affected_packages_check_idx` expression). Values are folded in Go. One arm when the correlated ecosystem values are all `PyPI` (fold with `ecosystem.FoldPackageName("PyPI", v)`) or contain no `PyPI` (fold with `FoldPackageName("npm", v)`, i.e. lower case). Otherwise (mixed, no ecosystem condition, or an `or` rule) two arms: `((cap.ecosystem = 'PyPI' AND <folded> = ANY(?)) OR (cap.ecosystem <> 'PyPI' AND <folded> = ANY(?)))` with the PyPI-folded and lower-cased lists. Each list is de-duplicated. |
| `contains`, `starts_with`, `ends_with` | `lower(cap.package_name) ILIKE ?`, pattern built as `affectedPackageSQL` builds it today (`escapeLike(strings.ToLower(v))` with `%`). |

Do NOT use `unnest()` joins, `NOT IN`, or a CTE for candidate IDs (DB-27; design 13 rejects a shared CTE). Do NOT lower-case ecosystems.

**Unit tests (SQL shape and args; write first):**
- `{and: ecosystem eq npm, package eq lodash}` → one predicate; SQL contains `cves.cve_id IN (SELECT cap.cve_id FROM cve_affected_packages cap`, `cap.ecosystem = ANY(`, no `LIKE ANY`, the folded-name expression, one arm; args `["npm"]`, `["lodash"]`; with candidates `["CVE-1"]` the first arg is the candidate array.
- `{and: ecosystem eq Debian, package eq openssl}` → `LIKE ANY` arm with `["Debian:%"]`.
- `{and: ecosystem in [npm, PyPI], package eq Foo_Bar}` → two arms with `["foo-bar"]` and `["foo_bar"]`.
- `{or: ecosystem eq npm, package eq lodash}` → two separate sets; the package set has two arms and no ecosystem line.
- `{and: ecosystem neq npm, package eq lodash}` → a `NOT EXISTS` predicate and a package set with no ecosystem line.
- `{and: ecosystem eq npm, package eq a, package eq b}` → two package sets, each with the npm line, and no standalone ecosystem set.
- `{and: ecosystem eq npm}` (no package) → one ecosystem set.
- `{and: package contains lodash}` → package set with `ILIKE`.
- `Where(nil)` emits no `cap.cve_id = ANY(` line; `Where([]string{"CVE-1"})` emits it once per set.
- `ecosystem.TakesSuffix("Debian")` true, `("npm")` false.
- Existing `dsl_test.go` tests that assert the old `affected.*` SQL text (`lower(cap.ecosystem) LIKE ANY`, per-row `EXISTS`) are rewritten to assert the new shape and bound values; the commit subject says "rewrite" for them. Integration tests of ecosystem and package rules (`internal/alert/ecosystem_match_test.go`, `internal/store/dsl_executor_test.go`) must pass unchanged, except a case that depends on uncorrelated matching, which is the documented meaning change (design 4.3): change it only with a comment naming design section 4.2, and list it under Deviations.

**Run:** `go test ./internal/alert/dsl/... ./internal/ecosystem/... -count=1`, then `go test ./internal/alert/... ./internal/store/... -count=1 -run 'Ecosystem|DSL'`.

### Task 2.4: Validation for package conditions and the 100-condition limit

**Files:** Modify `internal/alert/dsl/validator.go`, `internal/alert/dsl/compiler.go` (Compile re-applies the condition limit); Test `internal/alert/dsl/dsl_test.go`; Test `internal/api/alert_rules_test.go` (create/PATCH symmetry).

**Rules (messages verbatim from design section 8):**
- More than 100 conditions → rule-level error (index -1): `a rule may hold at most 100 conditions`. `Compile` returns an error for the same case, so a stored rule edited past the limit fails closed (`failUncompilableRule`).
- `affected.package` `eq` with an empty or whitespace-only string (`strings.TrimSpace(v) == ""`), or `in` holding one → error at that index: `value must not be empty`.
- `affected.package` `in` with no values → `value must list at least one item`. (Existing fields keep today's behaviour for empty `in`.)
- An `and` rule with at least one package condition and two or more correlated ecosystem conditions that no ecosystem satisfies together → rule-level error: `every ecosystem condition must hold on the same package row, and no ecosystem satisfies all of them, so this rule can never match; use one "in" condition if any of them is enough`.
  - Rule: a stored ecosystem `s` matches a value `v` when `s == v`, or `ecosystem.TakesSuffix(base(v))` and `strings.HasPrefix(s, v+":")`. The conditions are satisfiable together iff some value `w` drawn from any of the conditions is matched by at least one value of every condition. This is exact because matches are colon-prefix cones: if any stored ecosystem satisfies all conditions, the longest of the values that cover it is itself such a `w`.
  - Algorithm (linear, not a cross product): put each condition's values in a `map[string]bool`. For each distinct candidate `w`, the only values that can match it are `w` itself and its colon-prefixes (`w` cut at each `:`), at most a handful. A condition holds for `w` when its map contains `w`, or contains a colon-prefix `p` of `w` with `ecosystem.TakesSuffix(base(p))`. Cost is O(values × conditions × colons in a value). A request can carry tens of thousands of ecosystem values inside 1 MiB, so a pairwise comparison of values is not acceptable.
- `affected.package` `eq`/`in` in an `or` rule, or in an `and` rule with no correlated ecosystem condition → warning at that index: `without an ecosystem condition in an "and" rule, this match cannot narrow by ecosystem first and may be slow on PostgreSQL versions before 18`.

**Tests:**
- 100 conditions pass, 101 fail (error index -1); `Compile` on 101 returns an error.
- `package eq " "` refused; `package in []` refused; `package in ["a", ""]` refused at that index.
- Never-matching on large input: two `in` conditions of 30,000 distinct `Debian:<n>` and `Ubuntu:<n>` values plus a package condition are refused, and the test runs in the package's normal time (no timing assertion; the linear algorithm is what keeps it fast, and a quadratic one would make this test take minutes).
- Never-matching: refused for `{ecosystem eq npm, ecosystem eq PyPI, package contains x}`; allowed for `{ecosystem in [npm, PyPI], ecosystem eq npm, package eq x}` and `{ecosystem eq Debian, ecosystem eq Debian:13, package eq openssl}`; allowed for `{ecosystem eq npm, ecosystem eq PyPI}` with no package condition (no correlation) and for any `or` rule.
- Warning present for `{or: package eq lodash}` and `{and: package eq lodash}`; absent for `{and: ecosystem eq npm, package eq lodash}`; absent for `contains`.
- Create/PATCH symmetry (testing-pitfalls §4): in `internal/api/alert_rules_test.go`, the same never-matching conditions return 422 with the same error list from `POST .../alert-rules` and `PATCH .../alert-rules/{id}`. Follow that file's existing create/PATCH test pattern.

**Run:** `go test ./internal/alert/dsl/... -count=1`; `go test ./internal/api/... -count=1 -run AlertRule`.

### Task 2.5: Integration tests for correlation, exact match and the meaning change

**Files:** Create `internal/alert/package_match_test.go` (package `alert_test`; uses the existing `TestMain` in `internal/alert/main_test.go`; ABOUTME header). Follow `internal/alert/ecosystem_match_test.go`: build `feed.CanonicalPatch` values and ingest with `merge.Ingest(ctx, tdb.Store, patch, "osv")`; create rules with `mustRule` (which creates a `draft` rule) and then `activateRule` (`internal/alert/evaluator_test.go:114-140`; realtime and batch evaluate only `active` rules), or, for an activation test, create the rule with `Status: "activating"` as `TestEvaluatorActivation` does (`evaluator_test.go:521-545`; `EvaluateActivation` moves only an `activating` rule to `active`). Assert the rule's status before evaluating, so a negative case cannot pass because the rule was never evaluated. Then run `EvaluateRealtime` or `EvaluateActivation` and assert event rows. Tasks 3.3 and 5.6 use the same setup.

**Cases (design section 12, "Integration with hand-built patches"):**
- A CVE with npm `foo` and PyPI `lodash`: `{and: ecosystem eq npm, package eq lodash}` → no event; `{or: ...}` → event; `{and: ecosystem eq PyPI, package eq lodash}` → event.
- Folding: `package eq Foo_Bar` matches a PyPI `foo-bar` row, not an npm `foo-bar` row.
- `{and: ecosystem eq Debian, package eq openssl}` matches a `Debian:13` openssl row.
- `{and: ecosystem neq npm, package eq lodash}` does not match a CVE with PyPI `lodash` and any npm row.
- `{and: ecosystem eq npm, package eq a, package eq b}` matches a CVE with npm rows for `a` and `b`; not one with only `a`.
- A rejected CVE with a matching package does not match.
- Meaning change (design 4.3): a CVE with npm `foo` and PyPI `lodash` and an open event for `{and: ecosystem eq npm, package contains lodash}` (create the event under the pre-change reading by inserting it through `store.InsertAlertEvent` at the CVE's current hash — this simulates an event opened before this change, not CVE data); after `EvaluateRealtime` the event is resolved. This pins that old events resolve on next evaluation.

**After Phase 2 group:** Review the batch once, from a perspective the individual tasks did not apply (here: every existing `affected.*` rule shape in `dsl_test.go` and the store executor tests — did any change meaning other than the documented correlation and exact ecosystems?). Run further rounds only while the previous round produced material findings; stop when one produces none. A round run to reach a count, after findings have stopped, manufactures them — and a manufactured finding is the same defect as a suppressed one.

**Commit (Tasks 2.3–2.5 may be one commit or three, in order):** `feat(dsl): correlate package and ecosystem conditions and add exact package match` + log entry.

---

## Phase 3 — The `affected.cpe_product` field

**Execution Status:** ✅ SHIPPED 2026-11-14 on branch `claude/lucid-moser-fef966` — `76359bc` (3.1), `71b4e9b` (3.2), `ead194c` (3.3), `fcde2c5` (3.4). After-group review (independent adversarial reviewer, one round): no rule value reaches SQL text; worst valid rule about 5,100 parameters with 5,000 candidate IDs; one defect introduced by this branch, `Validate` ran the never-matching check (values times conditions) before the 100-condition limit, so a 1 MiB rule cost about 5 s of CPU per request; fixed in `d69081d`. A second round on the fix was not run: the fix only reorders an existing check behind an existing limit.

Design sections 3 (field), 5.1 (product SQL), 5.2 (compiler decisions), 8 (messages), 10 (AI prompt), 12 (tests).

### Task 3.1: Field registry and validation

**Files:** Modify `internal/alert/dsl/field.go`, `internal/alert/dsl/validator.go`; Test `internal/alert/dsl/dsl_test.go`.

**Changes:**
- New kind `kindProduct` ("affected.cpe_product: eq/in; CPE vendor:product"); registry entry `"affected.cpe_product": {kindProduct, "", []string{"eq", "in"}, false, nil}`; `ExportFieldDescriptions` gives `TypeDesc: "CPE vendor:product"`.
- `selectiveFields` gains `"affected.cpe_product": true`.
- `validateValue` for `kindProduct`: `eq` takes a JSON string, `in` a JSON array of strings; empty `in` → `value must list at least one item`; each value through `check.ParseProductValue`; a parse error is an error at that index with the parser's message.
- Rule-level product limit: within each `affected.cpe_product` condition, de-duplicate its normalised values (`ParseProductValue` result `Vendor+":"+Product`), then sum those per-condition counts over the rule; more than 50 → index -1 error `a rule may name at most 50 products in total`. `NodeJS:Node.js` and `nodejs:node\.js` in one condition count once; the same product in two conditions counts twice, because each condition compiles to its own set with its own parameters. Counting distinct values across the whole rule would let 100 conditions each list the same 50 products and compile to about 125,000 parameters, past PostgreSQL's 65,535. Sam confirmed this per-condition reading of design section 5.2 ("after normalisation and de-duplication") on 2026-11-14.
- Unmapped warning: for each distinct value where `check.NamesFor` reports `mapped == false` → warning at the condition's index: `no other CNA spelling is known for "x:y"; before NVD analyses a CVE, it matches only if the CNA record names vendor "X" and product "Y"`, where `x:y` is the normalised value and `X`/`Y` are the first name `NamesFor` returns (the own name with `_` read as a space).
- Any other operator on the field is already refused by the existing `operator %q is not valid for field %q` check; add a test.

**Tests:** each message row of design section 8 for the field; 50 values over several conditions pass, 51 fail; duplicates after normalisation within one condition count once; two conditions each naming `nodejs:node.js` count two; 100 conditions each listing the same 50 products are refused; warning for `example:widget`, none for `nodejs:node.js`; a regex rule with a product condition and no watchlist passes the regex-only guard. Extend Task 2.4's create/PATCH symmetry test in `internal/api/alert_rules_test.go` with a 51-product rule and a malformed value (`nodejs node.js`): both endpoints return 422 with the same error list.

**Run:** `go test ./internal/alert/dsl/... -count=1`; `go test ./internal/api/... -count=1 -run AlertRule`.

### Task 3.2: Compile the product set

**Files:** Modify `internal/alert/dsl/sets.go` (add `ProductSetSQL`, `OtherProductSQL`), `internal/alert/dsl/compiler.go`; Test `internal/alert/dsl/sets_test.go`.

**Exported API (exported because the Task 3.3 parity test in `internal/alert` calls them):**
```go
// ProductSetSQL is the CVE-ID set for one affected.cpe_product condition
// (design section 5.1): NVD vulnerable CPE rows under any CPE spelling of any
// value, and CNA rows carrying any name of a value but none of its other
// products. candidateIDs is repeated inside both branches when non-empty.
func ProductSetSQL(values []check.ProductRef, candidateIDs []string) sq.Sqlizer

// OtherProductSQL is the condition, over the lower-cased vendor and product
// SQL expressions given, under which a CNA row is one of others: vendor equal,
// product equal, or for a prefix starting with it and followed by nothing or by
// a character that is not an ASCII letter or digit (check.IsOtherProduct's rule).
func OtherProductSQL(vendorExpr, productExpr string, others []check.CNAName) sq.Sqlizer
```

**SQL built by `ProductSetSQL`:**
```sql
cves.cve_id IN (
    SELECT m.cve_id FROM cve_cpe_matches m
    WHERE m.vulnerable
      AND m.cve_id = ANY(?)                                        -- candidate line
      AND (<range> OR <range> ...)
    UNION ALL
    SELECT a.cve_id FROM cve_cna_affected a
    WHERE a.cve_id = ANY(?)                                        -- candidate line
      AND ( ((<name> OR <name> ...) [AND NOT (<other products of value 1>)])
         OR ((<name> ...) [AND NOT (<other products of value 2>)]) ... )
)
```
- `<range>` for each CPE spelling `c` in `NamesFor(value)`'s `cpes` and each part in `a`, `o`, `h` (de-duplicated across values): `k := check.CPEKeyFor("cpe:2.3:" + part + ":" + c + ":")`, emitted as `(E >= ? AND E < ? AND starts_with(m.cpe_normalized, ?))` with `E = check.CPEIndexExpr("m.cpe_normalized")` and args `k.Lo, k.Hi, k.Prefix`.
- `<name>` for each name `n` of the value: `k := check.CNANameKeyFor(n)`. Exact name (`k.FullProduct != ""`): `(V = ? AND P = ? AND lower(a.vendor) = ? AND lower(a.product) = ?)` with args `k.V, k.Lo, k.FullVendor, k.FullProduct`. Prefix name: `(V = ? AND P >= ? AND P < ? AND lower(a.vendor) = ?)` with args `k.V, k.Lo, k.Hi, k.FullVendor`. `V = check.CNANameIndexExpr("a.vendor")`, `P = check.CNANameIndexExpr("a.product")`.
- The `AND NOT (...)` group is present only when `check.OtherProductsFor(value)` is non-empty, and covers only that value's group (design 5.1: `in [microsoft:.net, microsoft:.net_framework]` must still match `Microsoft` / `.NET Framework` through the second value).
- `OtherProductSQL(vendorExpr="lower(a.vendor)", productExpr="lower(a.product)")`: for each other `o`: exact → `(vendorExpr = ? AND productExpr = ?)`; prefix → `(vendorExpr = ? AND starts_with(productExpr, ?) AND substr(productExpr, char_length(?) + 1) !~ '^[a-z0-9]')` with `o.Vendor, o.Product, o.Product` (all lower case in the table). Rows reaching this test matched a name term, so their vendor and product are non-NULL.
- `Compile` for a product condition: parse every value with `check.ParseProductValue` (a stored rule with a bad value fails compile, so the evaluator sets `status=error`), de-duplicate within the condition, apply Task 3.1's 50-value count across the rule, and register `predicate(func(c []string) sq.Sqlizer { return ProductSetSQL(values, c) })`.
- `affected.cpe_product` is never correlated with package conditions (design 4.2).

**Tests (write first):**
- `nodejs:node.js` with no candidates: 38 args (18 range + 20 name; design 3.2) and the SQL contains three `starts_with(m.cpe_normalized` per CPE spelling, no `cve_id = ANY`; with one candidate: 40 args.
- `microsoft:.net`: the CNA branch contains `NOT (` and a `!~ '^[a-z0-9]'`; `in [microsoft:.net, microsoft:.net_framework]`: two value groups, the `NOT` inside the first only.
- Values are only arguments: compile `nodejs:node.js` and assert no arg value appears literally in the SQL text.
- A stored rule with value `nodejs node.js` makes `Compile` return an error; one with 51 product values too.
- Parameter bound: build the worst rule the validator accepts — 50 product values in one-value conditions, using every CPE in the name table (the mapped rows carry the most CPE spellings, names and other products) and filling the rest with unmapped values that have `_` in both vendor and product (four own names each) — plus 50 `affected.package` `in` conditions; `Validate` returns no error, and `Where` with 5,000 candidate IDs returns fewer than 10,000 args. Record the actual count in the test name or a comment.

### Task 3.3: Integration tests for products

**Files:** Create `internal/alert/product_match_test.go` (package `alert_test`, ABOUTME header).

**Cases (design section 12):**
- **Parity:** for every entry of `check.OtherProductsFor` over the table's CPEs (`microsoft:.net`, `microsoft:.net_core`, `openssl:openssl`) and for each other product's name followed by `a`, `7`, ` `, nothing and `é`: the database's answer equals `check.IsOtherProduct(others, vendor, product)`. Build the statement entirely with squirrel so it numbers every placeholder: `sq.Select().Column(dsl.OtherProductSQL("lower(t.v)", "lower(t.p)", others)).FromSelect(sq.Select().Column(sq.Expr("?::text AS v", vendor)).Column(sq.Expr("?::text AS p", product)), "t").PlaceholderFormat(sq.Dollar)`. Do NOT write literal `$1`/`$2` into the expressions: squirrel's `Dollar` numbering does not skip them and would collide.
- **SeedCorpus** (`testutil.SeedCorpus(t, tdb)`): `{and: affected.cpe_product eq fastify:fastify, severity in [critical, high, medium, low]}` matches CVE-2026-107832 (assert the stored severity is `LOW` first, so a fixture change fails loudly); the same without `low` does not match. `nodejs:node.js` matches CVE-2026-56847 and CVE-2026-111497. `google:brotli` matches CVE-2026-111497.
- **Same answer on every path (design 12):** for a set of rules (`nodejs:node.js`; `google:brotli` `or` `in_cisa_kev eq true`; `{and: ecosystem eq npm, package eq fastify}`; `{or: package eq lodash, cpe_product eq nodejs:node.js}`; `{and: ecosystem neq npm, severity eq high}`), the CVE IDs from `store.ExecuteDSLQuery` paged to the end equal the CVE IDs of the events `EvaluateActivation` writes. `DryRun`'s `MatchCount` equals the same count.
- **Hand-built patches** (through `merge.Ingest`):
  - CNA `Node.js` / `Node.js` and `The Node.js Project` / `Node.js` each match `nodejs:node.js`.
  - `.NET 9.0 runtime` matches `microsoft:.net`; `.NET Framework 4.8` and `OpenAPI.NET` do not; `.NET FrameworkExtensions` does. `in [microsoft:.net, microsoft:.net_framework]` matches `Microsoft` / `.NET Framework` (built CNA row).
  - Full-name recheck: rule values are at most 255 characters, so no rule can produce a vendor whose 256-character index key collides with a longer stored vendor; the recheck is tested below the parser. Call `dsl.ProductSetSQL([]check.ProductRef{{Vendor: a, Product: "widget"}}, nil)` directly with `a = strings.Repeat("x", 256) + "a"` (257 characters), against two built CNA rows with product `widget`: vendor `a` (matches) and vendor `strings.Repeat("x", 256) + "b"` (same 256-character key, different full name; must not match). Falsification probe, once: drop the `lower(a.vendor) = ?` term from the exact-name SQL, confirm the second row then matches, restore.
  - A CVE whose only Node CPE match is `vulnerable: false` does not match.
  - A rejected CVE with a matching product does not match.
- **Acceptance (design 15.2):** take `p := testutil.GoldenPatch(t, "nvd", "CVE-2026-56847")` (its CNA entry names `nodejs` / `node`); set `p.CVEID` to an unused ID, clear `p.CPEMatches` and `p.AffectedCPEs`, and set `p.Severity` to `"HIGH"` (clear CVSS scores if the merge would derive another severity from them; assert `cves.severity` is `HIGH` after ingest). Ingest with `merge.Ingest(ctx, tdb.Store, p, "nvd")`, then `EvaluateRealtime`: the rule `{and: affected.cpe_product eq nodejs:node.js, severity in [critical, high]}` creates one event. Then ingest an NVD patch adding a vulnerable `cpe:2.3:a:nodejs:node.js:*:...` match and affected CPE: `material_hash` changes, realtime runs, and a second event exists at the new hash (design 3.5 step 2).

**Run:** `go test ./internal/alert/... -count=1 -run 'Product|Package|Parity|EveryPath'`.

### Task 3.4: AI prompt notes

**Files:** Modify `internal/ai/schema.go:61-66`; Test `internal/ai/schema_test.go`.

Add three note lines (design section 10), after the existing notes:
```go
b.WriteString("- \"affected.cpe_product\" takes \"vendor:product\" from a CPE name, such as \"nodejs:node.js\".\n")
b.WriteString("- In an \"and\" rule, \"affected.ecosystem\" and \"affected.package\" describe the same package, so name the package's ecosystem with it.\n")
b.WriteString("- \"affected.package\" with \"eq\" matches a whole package name.\n")
```
Test: `BuildSchemaDescription()` contains `affected.cpe_product (type: CPE vendor:product)` and the three notes. `PromptVersion` changes by itself.

**Run:** `go test ./internal/ai/... -count=1`.

**Commit (Tasks 3.1–3.4, one or several commits in order):** `feat(dsl): match alert rules by CPE vendor and product` + log entry.

**After Phase 3 group:** Review the batch once, from a perspective the individual tasks did not apply (here: an adversarial caller — can any rule value reach the SQL text, exceed the parameter budget of design 3.2, or compile differently in `Validate` and `Compile`?). Run further rounds only while the previous round produced material findings; stop when one produces none. A round run to reach a count, after findings have stopped, manufactures them — and a manufactured finding is the same defect as a suppressed one.

---

## Phase 4 — Measurements on the kept full ingest (gate)

**Execution Status:** ✅ COMPLETE 2026-11-14 — every statement threshold passes after Sam's remedy; M8 accepted by Sam (decisions below). History: the first run failed the gate (Task 4.3). Failing rows then: M5a limit rule `or` realtime 23.3 ms (threshold 5 ms); M5b dry-run and M5c batch failed with a shared-memory error (64 MB `/dev/shm`), and serially take 27.6 s and 17.7 s (thresholds 5 s, 3 s); M6 50 products `or` dry-run 16.2 s (5 s); M8 full activation failed on page 1 with the shared-memory error. Every single-product, package-with-ecosystem and saved-search row passes. Full table, inputs and a read-only sweep of smaller limits: `dev/plans/2026-11-13-product-match-rules-measurements.md`. **Unblock condition:** Sam chooses the remedy (design section 13's fallback is a lower limit on set-type conditions); the chosen limits are re-measured with this harness before Phase 5 starts. The disposable copy `cvert-match2-activation-copy` is kept for that re-measurement and Task 5.5.

**Sam's decision (2026-11-14):** the remedy is not a lower limit. Under `or`, every set-type condition compiles into one CVE-ID set (`cves.cve_id IN (<branch> UNION ALL ...)`, candidate IDs inside each branch), with scalar conditions OR-ed beside it; under `and`, one set per condition as before. The evaluator's candidate statement runs with `SET LOCAL jit = off`. Evidence for it: OR-ed `IN` subqueries cannot become semi-joins, so each is a hashed SubPlan built in full; the 50 package names in one `IN` planned as a merge semi-join in about 100 ms; JIT cost about 4 s on a 50-product dry-run (`bea8e03`). The limits (50 product values, 100 conditions) stay. Expected to remain open after it: realtime planning of a 50-product rule (10.7 ms in the two-condition form against 5 ms), which merging conditions does not reduce. Re-measure all of Task 4.2 at the original limits.

**Re-measured after the merge and JIT off (`7ad8080`):** M6 passes (16.2 s → 0.6 s); the limit rule still fails: realtime 81 ms (a parallel plan for one CVE, 16 ms planning), dry-run 11.0 s, batch shared-memory error (serially 4.7 s, 2.0 s of it planning the 5,000-ID array repeated in about 150 branches).

**Sam's second decision (2026-11-14, "Yes, both"):** keep the merged `or` set and JIT off, and when a statement has candidate IDs (realtime, batch, EPSS, activation), match the product set's CPE prefixes and CNA names against bound arrays instead of OR-ed terms, so planning does not grow with the number of products; with no candidate IDs (dry-run, saved searches) keep the OR-ed range form for the check indexes. Both forms must give the same answers. Limits unchanged. Re-measure every Phase 4 row and the original limit rule; if a row still fails, report the numbers to Sam before choosing another remedy. Record the section 5 change as a design amendment.

**Re-measured after both changes (`7ad8080`, `fe0e32f`; 2026-11-14):** M6 passes (0.6 s); candidate-statement planning no longer grows with the number of products (limit rule realtime planning 18.6 → 6.5 ms). Still failing: M5a realtime 26.4 ms; M5b dry-run 11.0 s (no candidates; the 50 no-ecosystem kernel package sets); M5c batch 3.2 s; M8 read-only estimate about 22 minutes with a shared-memory error at page 1,422. Single-product batch rows pass but rose to up to 505 ms (parallel sequential scans of `cve_cpe_matches` and `cve_cna_affected` under the array form). Reported to Sam before any further remedy; Phase 4 is ⏸ until he decides.

**Sam's third decision (2026-11-14, "Yes, both"):** evaluator rule statements also run with parallel query off (`SET LOCAL max_parallel_workers_per_gather = 0`), and under `or` all `affected.package` `eq`/`in` conditions compile into one package branch (exactly equivalent: they are uncorrelated under `or`). Then re-measure; the dry-run limit for no-ecosystem package names is decided with the new number.

**Re-measured after `9d58ee1` (2026-11-14):** every statement threshold passes (M5a realtime 4.7 ms, M5b dry-run 4.3 s, M5c batch 0.45 s, M6 1.4 s; M7d equal to the old form when interleaved), so no dry-run limit is needed. M8 full activation on the copy completed (rule `active`, 200,252 events) in 12 min 5 s against 7 minutes: about 4 minutes of reads and 8 of one-transaction-per-event inserts, a cost that follows the match count (`severity in [critical, high]` matches 182,637 CVEs). Design amendment written: `dev/plans/2026-11-13-product-match-rules-design.md` section 17. M8 is with Sam.

**Sam's decision on M8 (2026-11-14, "Accept, follow up"):** M8 is accepted for MATCH-2 as a limit of the existing activation path (per-event insert transactions), not of the rule shape. Batching activation event inserts is a separate follow-up, started as its own session and branch from `dev` ("Batch alert event inserts in activation scans"); its PR's own record signals completion. Phase 4 is complete. **Re-measured after PR 243 merged into this branch (`e72f6a9`): M8 full activation 2 min 4 s, 200,252 events — passes.**

Design section 13 (every measurement and threshold) and section 5.3 (earlier numbers to compare against). This phase changes no production code. Its result decides whether Phase 5 starts or the work goes back to Sam.

**The kept ingest is kept data.** Docker container `cvert-check-ingest-postgres` holds a complete ingest (about 2.6 million CVEs, PostgreSQL 18). It is never scratch:
- Never stop, restart, `docker rm`, `docker compose down`, or write to it. Do not drop caches. A feed worker owned by another session may be writing to it; leave it alone.
- Every connection is read-only: the DSN carries `options=-c default_transaction_read_only=on`, the harness checks `SHOW default_transaction_read_only` returns `on` before its first statement, and every statement runs inside `BEGIN READ ONLY`.
- Run Docker commands from the PowerShell tool (the Bash tool's guard refuses `docker`).

### Task 4.1: Pre-flight checks on the kept ingest

1. `docker inspect -f '{{.State.Running}}' cvert-check-ingest-postgres` → `true`. If not running, STOP and ask Sam; do not start it.
2. Write a PowerShell script in the session scratchpad (never in the repository) that reads the connection settings into variables without echoing them — `docker port cvert-check-ingest-postgres 5432` for the host port, `docker exec cvert-check-ingest-postgres printenv POSTGRES_USER`, `POSTGRES_DB` and `POSTGRES_PASSWORD` — sets `$env:KEPT_INGEST_DATABASE_URL = "postgres://127.0.0.1:${port}/${db}?sslmode=disable&options=-c%20default_transaction_read_only%3Don"` (no credentials in the URL), `$env:KEPT_INGEST_USER` and `$env:KEPT_INGEST_PASSWORD`, and then runs the Task 4.2 command in the same process. The password must never appear in tool output, logs or files; a URL holding it would be echoed by `url.Parse` errors, which pgx returns verbatim. If `POSTGRES_PASSWORD` is empty (the container may use a password file), STOP and ask Sam how to connect.
3. Through `docker exec -i -e PGOPTIONS="-c default_transaction_read_only=on" cvert-check-ingest-postgres psql -X -v ON_ERROR_STOP=1 -U <user> -d <db>` (read-only from connection start; `-X` skips startup files) with a file that begins `BEGIN READ ONLY;` then `SHOW transaction_read_only;` (must print `on`; the file stops otherwise because of `ON_ERROR_STOP` and a following `DO $$ BEGIN IF current_setting('transaction_read_only') <> 'on' THEN RAISE EXCEPTION 'not read-only'; END IF; END $$;`), and ends `ROLLBACK;`, record: `SELECT max(version) FROM schema_migrations;`, and `SELECT indexname, indexdef FROM pg_indexes WHERE indexname IN ('cve_cpe_matches_check_idx','cve_cna_affected_check_idx','cve_affected_packages_check_idx','cve_cpe_matches_cve_id_idx','cve_cna_affected_cve_id_idx','cve_affected_packages_cve_id_idx');`. Each check index's expression must match what the code emits (`check.CPEIndexExpr`, `check.CNANameIndexExpr`, `ecosystem.FoldedNameSQL`). If one differs (for example the database predates migration 61's `left(cpe_normalized, 512)`), STOP and report to Sam: a measurement against a different index measures a different plan.

### Task 4.2: The measurement harness

**Files:** Create `internal/alert/kept_ingest_measure_test.go` with build tag `//go:build keptingest` (so the normal suite never runs it), package `alert` (internal test, so it can call `candidateQuery` from Task 2.2), ABOUTME header: "Measures compiled rule statements on a kept full ingest, read-only (design section 13)" / "Runs only with -tags keptingest and KEPT_INGEST_DATABASE_URL; never writes".

**Rules for the harness:**
- The package's `TestMain` (`internal/alert/main_test.go`, `testutil.Run`) starts the shared test container only on the first `testutil.NewTestDB` call, so a run with `-run KeptIngest` starts none. The measurement test calls `t.Skip` unless `KEPT_INGEST_DATABASE_URL` is set, and never calls `testutil.NewTestDB`.
- Open the pool as `internal/testutil/postgres.go` does: `cfg, err := pgx.ParseConfig(os.Getenv("KEPT_INGEST_DATABASE_URL"))`, then `cfg.User` and `cfg.Password` from `KEPT_INGEST_USER` and `KEPT_INGEST_PASSWORD`, then `cfg.DefaultQueryExecMode = store.DefaultQueryExecMode` (production's mode, `internal/store/store.go:17-22`; pgx's own default differs), then `stdlib.OpenDB(*cfg)` (`github.com/jackc/pgx/v5/stdlib`). Never log `cfg` or a connection error wrapped with it; on a connect failure report only the error class and host:port. Verify once with sentinel credentials containing `/` and `@` that a failing connect prints neither. Assert `SHOW default_transaction_read_only` is `on`, `SET statement_timeout = '60s'` per transaction (`SET LOCAL` inside `BEGIN READ ONLY`), so a slow statement is measured rather than cut at the production 14 s.
- Each statement runs as `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` three times; report the first run ("first run"; the design's "cold" figures were first runs, and caches are never dropped) and the median of runs 2 and 3 ("warm"), each with planning and execution time.
- Statements come from production code: `candidateQuery(compiled, ids)` for realtime, batch and dry-run; for the saved-search shape, the harness rebuilds `ExecuteDSLQuery`'s statement (columns, `Where(nil)`, status filter, `ORDER BY cves.date_modified_canonical DESC, cves.cve_id DESC LIMIT 51`) — keep it identical to `internal/store/dsl_executor.go` and say so in a comment.
- Output: a Markdown table written to `dev/plans/2026-11-13-product-match-rules-measurements.md` (rows below; columns: measurement, statement shape, first run planning/execution, warm planning/execution, rows, plan notes such as "hashed SubPlan", threshold, pass/fail).

**Inputs, chosen by read-only queries in the harness:**
- Realtime CVE: `CVE-2024-26581` (design Appendix A; a `linux:linux_kernel` CVE). Batch: the 5,000 most recently modified CVE IDs (`ORDER BY date_modified_canonical DESC LIMIT 5000`).
- The 50 products with the most vulnerable CPE rows: `SELECT split_part(cpe_normalized, ':', 4) || ':' || split_part(cpe_normalized, ':', 5) AS vp, count(*) FROM cve_cpe_matches WHERE vulnerable GROUP BY 1 ORDER BY 2 DESC LIMIT 80`, then keep the first 50 that `check.ParseProductValue` accepts (a split on escaped colons is refused by the parser and skipped). The first must be `linux:linux_kernel`; record the list.
- The 50 package names: `SELECT <folded name expr> AS n, count(*) FROM cve_affected_packages GROUP BY 1 ORDER BY 2 DESC LIMIT 50`.

**How a time is compared with its threshold:** the compared figure is planning time plus execution time, from the warm median (runs 2 and 3). A row passes when that figure is at or under its threshold. The first run is reported beside it; a first run over the threshold with a passing warm figure is flagged to Sam in the results file, not counted as a failure, except where a row below says "first run". The M8 activation is wall-clock time of `EvaluateActivation`. The table keeps planning and execution as separate columns.

**Measurements (design section 13; each with its threshold):**

| # | Measurement | Threshold that goes back to Sam |
|---|---|---|
| M1 | Realtime, one CVE, `linux:linux_kernel`, `and` and `or in_cisa_kev` | over 5 ms |
| M2 | Batch, 5,000 IDs, `linux:linux_kernel` `and` / `or`; `nodejs:node.js` `and` | over 3 s |
| M3 | Dry-run, `nodejs:node.js` with severity critical/high `and`; `nodejs:node.js` alone; `or in_cisa_kev`; `linux:linux_kernel` alone and `or in_cisa_kev` | over 5 s |
| M4 | Saved-search shape, `linux:linux_kernel` | over 5 s (dry-run threshold) |
| M5 | Limit rule (50 one-value product conditions + 50 one-value package `eq` conditions, no ecosystem) under `or`: realtime, dry-run, batch 5,000 IDs, with planning time in its own column and counted in the compared figure. Also under `and` for information (design 13: `or` is the worst case and the one thresholds apply to) | realtime over 5 ms; batch over 3 s; dry-run over 5 s |
| M6 | `or` rule of the 50 products, dry-run: the plan JSON shows a hashed SubPlan (`"hashed SubPlan"` in the filter text). If not hashed, record it and apply the dry-run threshold | over 5 s |
| M7 | Package array forms, dry-run: `npm` with `in` of the 50 names; `Debian` with `eq openssl`; `eq openssl` with no ecosystem; `contains lodash` with no ecosystem in the set form, compared with the pre-Phase-2 form, `EXISTS (SELECT 1 FROM cve_affected_packages cap WHERE cap.cve_id = cves.cve_id AND lower(cap.package_name) ILIKE '%lodash%')` (today's `affectedPackageSQL`, `internal/alert/dsl/compiler.go:347-369`; the design measured it at 4.7 s), written out in the harness for comparison only | no-ecosystem `eq` over 5 s first run (revisits design 15.2 "Exact package match with no ecosystem"); no-ecosystem `contains` slower than today's form on the same run; others over 5 s |
| M8 | Full activation scan of the limit rule under `or`, on a disposable restored copy (method below) | over 7 minutes |

**M8 method.** Design 13 requires a full activation scan, which writes `alert_events` (`InsertAlertEvent` opens a transaction and takes the organisation's feed lock per match, `internal/store/alert_rule.go:339`). The kept ingest is read-only, so the scan runs on a disposable copy:

1. **Preliminary estimate (kept ingest, read-only):** the harness walks the corpus as `EvaluateActivation` does (`getCVEsBatch`'s keyset query, pages of 1,000 IDs), runs `candidateQuery` per page and `SELECT EXISTS(SELECT 1 FROM cves WHERE cve_id = $1)` per matched CVE, and reports the read time and the match count. If the read time alone exceeds 7 minutes, M8 fails without step 2.
2. **Full activation (disposable copy):** restore the kept ingest's most recent backup into a new container with its own new volume (for example container `cvert-match2-activation-copy`), never touching the kept container or volume. Ask Sam for the backup's location (it is recorded outside this repository) and check free disk on the Docker host before restoring; if there is not room for a full restore, STOP and ask Sam. Migrate the copy to this branch's head, create an org and the limit rule under `or` through the store, and time `EvaluateActivation` from a small `go test -tags keptingest -run KeptIngestActivation` test pointed at the copy by `KEPT_INGEST_COPY_DATABASE_URL`. M8 passes only on this run. Keep the copy for Task 5.5's batch-scan measurement; after that, remove the copy's container and volume, checking by name first that they are the copy's.

Record both numbers. If step 2 cannot be run (no backup access, no disk), M8 is not passed: set Phase 4 to ⏸ with that reason and ask Sam whether the step 1 estimate is enough.

**Run:** the Task 4.1 script, from the worktree, ends with
`go test -tags keptingest ./internal/alert/ -run KeptIngest -count=1 -timeout 120m -v 2>&1 | Tee-Object kept-ingest-measure.log` (the log goes in the scratchpad or is git-ignored; it is not committed). Read the log; do not rerun to "check" a number.

### Task 4.3: Decide the gate

- Every threshold passes → write the results file, commit it and the harness (`test(alert): measure product and package rule statements on the full ingest` + log entry with the summary table), flip Phase 4 to ✅, start Phase 5.
- Any threshold fails → commit the results file and harness anyway (evidence), set Phase 4 to ⏸ DEFERRED with the failing rows, and STOP. Ask Sam, quoting the failing rows. Recommended remedy from design 13 when the limit rule fails the batch threshold: a lower limit on set-type conditions only (`affected.cpe_product`, `affected.package`, and `eq`/`in` ecosystem conditions in a rule with no package condition), keeping 100 for scalar conditions. Do not implement a remedy before Sam answers. A shared candidate CTE is not a remedy (design 13).

**Note on the batch candidate scan (Phase 5):** its new `UNION` branch reads `date_match_inputs_changed`, which the kept ingest does not have (and must not be given). Task 5.5 measures it on the disposable copy, which is therefore kept until then.

---

## Phase 5 — Re-check signal

**Execution Status:** ✅ SHIPPED 2026-11-14 on branch `claude/lucid-moser-fef966` — code: `fdbf47f` (5.1–5.2, migration 000063), `3232759` (5.3), `ce2b731` (5.4–5.6); verify-first span 5.3 confirmed (ASCII-only lower-casing separates KELVIN SIGN + `node` from `knode`; `strings.ToLower` does not). Task 5.5's measurement on the copy fails its 3 s per-page threshold in one case (a sparse window's first page, 3.7 s); **Sam accepted it on 2026-11-14 ("Accept, record it")**: it occurs only when a window holds more than a page of changes clustered at high CVE IDs, stays far under the 14 s statement timeout, and the existing arm alone already takes 1.27 s on that page. Paging by `(date, cve_id)` would remove it and is left for a later change if backlogs matter. Merged `origin/dev` (`e72f6a9`, PR 243 batched activation inserts) before re-measuring M8.

Design section 7 (Sam's ruling 15.1: a separate signal, not a `material_hash` change) and section 12's re-check tests. `material_hash` and its golden hashes do not change (design 16): run `go test ./internal/merge/... -run 'Hash|Golden'` at the end of the phase and confirm no golden file changed.

### Task 5.1: Schema review

Invoke the `schema-review` skill on this change before writing SQL: `cves` gains `match_inputs_hash text NULL` and `date_match_inputs_changed timestamptz NULL`, and a partial index `cves_date_match_inputs_changed_idx ON cves (date_match_inputs_changed) WHERE date_match_inputs_changed IS NOT NULL`, created `CONCURRENTLY` (design 7.2). `cves` is global (no `org_id`, no RLS). Adding a nullable column with no default rewrites no rows. Record the skill's findings in the implementation-log entry; fix or take to Sam each one (never drop one).

### Task 5.2: Migration

Invoke the `migration` skill to write `migrations/000063_match_inputs_recheck.up.sql` / `.down.sql` (number per Setup step 4). Required content:
- First line of both files: `-- migrate:no-transaction` (the runner then executes each statement in its own autocommit; see `migrations/000061_bounded_cpe_and_package_keys.up.sql` for the house style and comment).
- Up: `ALTER TABLE cves ADD COLUMN IF NOT EXISTS match_inputs_hash text;`, `ALTER TABLE cves ADD COLUMN IF NOT EXISTS date_match_inputs_changed timestamptz;`, `CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_match_inputs_changed_idx ON cves (date_match_inputs_changed) WHERE date_match_inputs_changed IS NOT NULL;`
- Down: `DROP INDEX CONCURRENTLY IF EXISTS cves_date_match_inputs_changed_idx;` then drop both columns `IF EXISTS`.
- No semicolons inside SQL comments (golang-migrate splits on `;`).
- Test: follow `migrations/alert_events_feed_seq_test.go`: migrate up, assert both columns exist and are nullable and the index is partial with that predicate; migrate down and assert they are gone.

**Run:** `go test ./migrations/... -count=1`.

### Task 5.3: Compute and store `match_inputs_hash` in merge

**Files:**
- Modify: `internal/store/queries/cves.sql` (`UpsertCVE`), then `sqlc generate`
- Create: `internal/merge/match_inputs.go` (ABOUTME: "Computes match_inputs_hash: the rule match inputs that are not material_hash inputs" / "CNA vendor and product names and the part:vendor:product of NVD vulnerable CPE matches (design section 7)")
- Modify: `internal/merge/pipeline.go:159-203` (`canonicalize`)
- Modify: `internal/check/cpe.go` (export `CPEProductKey(cpeNormalized string) string`: `part:vendor:product` from a CPE 2.3 string split on unescaped colons with `splitCPE`, escapes as stored; "" when it has fewer than 5 components). `internal/merge` importing `internal/check` creates no cycle: `go list -deps ./internal/check` lists only `internal/ecosystem` and `internal/version` from this module (checked 2026-11-13); re-run it before committing.
- Test: `internal/merge/match_inputs_test.go` (unit), `internal/merge/pipeline_test.go` or a new integration test file in `internal/merge` (check it has a `TestMain` calling `testutil.Run`)

**Hash:** `ComputeMatchInputsHash(cna []feed.CNAAffected, cpe []feed.CPEMatch) string` = sha256 hex of JCS (`jsoncanonical.Transform`, as `ComputeMaterialHash` does in `internal/merge/hash.go`) of
```json
{"cna": [["<lower(vendor)>", "<lower(product)>"], ...], "cpe": ["<part:vendor:product>", ...]}
```
Both lists sorted and distinct; a missing vendor or product is `""`; only `Vulnerable == true` matches contribute; nil lists encode as `[]`. Lower-case only ASCII `A`–`Z` (a `strings.Map` over the string), not `strings.ToLower`: Go's full Unicode lower-casing maps KELVIN SIGN to `k`, while PostgreSQL's `lower()` under some database character types does not, so a CNA name changing from KELVIN SIGN (U+212A) followed by `node`, to `knode` would change a SQL match without changing a `strings.ToLower` hash. Two strings that are equal after ASCII lower-casing differ only in ASCII case, which every `lower()` folds alike, so the ASCII form never hides a change the match can see; at worst it re-checks a CVE whose match did not change, which sends no duplicate alert.
> **Verify-first (plan review round 8, unverified repair):** this ASCII-only rule replaced `strings.ToLower` in the last review wave and was not re-reviewed. Before building, confirm with a unit test that `Node.js`/`node.js` copies give one hash and that `string(rune(0x212A)) + "node"` versus `knode` gives two. Do NOT put these inputs into `MaterialFields` (Sam's ruling, design 15.1).

**UpsertCVE SQL:** add `match_inputs_hash` and `date_match_inputs_changed` to the insert column list with values `$19` and `$5` (a new CVE gets the merge clock), and to `DO UPDATE`:
```sql
date_match_inputs_changed = CASE
    WHEN cves.match_inputs_hash IS DISTINCT FROM EXCLUDED.match_inputs_hash
    THEN EXCLUDED.date_modified_canonical
    ELSE cves.date_match_inputs_changed
END,
match_inputs_hash = EXCLUDED.match_inputs_hash
```
A stored NULL is "distinct", so the first merge of each CVE after this ships stamps it once (design 7.1). `date_modified_canonical` keeps its own CASE on `material_hash` only.

**sqlc in a CRLF checkout:** after `sqlc generate`, list real changes with `git diff --ignore-cr-at-eol --stat`, restore the files with only line-ending changes (`git restore -- internal/store/generated ':!internal/store/generated/<changed>.go'`), and confirm with `git status --short`. New `generated.CVE` fields are not exposed by the API; grep hand-written scans of `generated.CVE` (`internal/store/dsl_executor.go` `cveColumns`, and any `SELECT *` scanned positionally) and confirm they still compile and scan the same columns.

**Tests:**
- Unit: hash is stable under reordering and duplicates; ASCII case-only differences between two CNA copies (MITRE `Node.js` vs NVD relay `node.js`) give the same hash; `string(rune(0x212A)) + "node"` and `knode` give different hashes; a vulnerable flag flip changes it; a non-vulnerable match does not contribute; adding a CNA row changes it; versions changes do not.
- Integration (never assume two clock readings are ordered: testing-pitfalls, "Database clock readings are not ordered across transactions"; the merge stamps with Go's `time.Now()`): ingest a CVE → `match_inputs_hash` set and `date_match_inputs_changed` equals `date_modified_canonical` (both from one statement's `$5`). Before each re-ingest, set `date_match_inputs_changed` to the fixed value `2000-01-01T00:00:00Z` and record `date_modified_canonical`. Re-ingest with only a CNA product change → `material_hash` and `date_modified_canonical` unchanged, `match_inputs_hash` changed, `date_match_inputs_changed` no longer `2000-01-01`. Re-ingest unchanged → `match_inputs_hash` unchanged and `date_match_inputs_changed` still exactly `2000-01-01`. Set the stored hash to NULL via the store's test DB handle (this is a column on an existing row, not CVE seeding), re-ingest → stamped once.

**Run:** `go test ./internal/merge/... ./internal/check/... -count=1`.

### Task 5.4: Realtime trigger in the ingest handler

**Files:** Modify `internal/store/cve.go:32-40` (`GetCVEMaterialHash` becomes `GetCVEChangeHashes(ctx, cveID) (CVEChangeHashes, error)` with `type CVEChangeHashes struct{ Material, MatchInputs string }`, empty strings when the row or value is missing), `internal/ingest/handler.go:52-56,182-228` (interface and comparison), `internal/ingest/handler_test.go:661` (mock).

**Behaviour:** read both before and after the merge; run `EvaluateRealtime` when `before != after` (struct equality) and both reads succeeded. Update the handler's comments that say "material_hash changes" to say "material_hash or match_inputs_hash changes". `GetCVEMaterialHash` has no other callers (confirmed by grep); remove it.

**Tests:** handler unit tests with the mock: realtime runs when only `MatchInputs` changes; does not run when neither changes; still runs when only `Material` changes; a failed pre-read skips evaluation as today.

**Run:** `go test ./internal/ingest/... ./internal/store/... -count=1 -run 'Handler|CVE'`.

### Task 5.5: Batch candidate scan

**Files:** Modify `internal/alert/evaluator.go:718-751` (`getCVEsModifiedSince`); Test `internal/alert/evaluator_test.go` or a new `internal/alert/match_inputs_recheck_test.go`.

**Change:** the two `since` cases become a `UNION` of two keyset scans (design 7.1), each able to use its own index and each limited to the page size, so a page never de-duplicates the whole eligible set:
```sql
(SELECT cve_id FROM cves WHERE date_modified_canonical > $1 [AND cve_id > $2] ORDER BY cve_id LIMIT $n)
UNION
(SELECT cve_id FROM cves WHERE date_match_inputs_changed > $1 [AND cve_id > $2] ORDER BY cve_id LIMIT $n)
ORDER BY cve_id ASC LIMIT $n
```
The first `$n` IDs of the union are always among the first `$n` of each branch, so the inner limits do not change the result. An integration test pins that: with 3 CVEs eligible only by `date_modified_canonical`, 3 only by `date_match_inputs_changed`, and 2 by both, interleaved by ID, pages of 2 return all 8 IDs once, in order.

**Measurement (on the Phase 4 disposable copy, never the kept ingest):** with the copy migrated to this branch's head, run `UPDATE cves SET date_match_inputs_changed = date_modified_canonical` on the copy, which models the state after every CVE has been merged once since the deploy. Then run `EXPLAIN (ANALYZE, BUFFERS)` of this statement for the first page and a later page, with `since` one day back and the evaluator's page size of 1,000. Record the plans and times in the measurements file; over 3 s per page goes to Sam, as the batch threshold does. Then remove the copy as Phase 4 says.
The zero-`since` cases (full scan) are unchanged. `cursorRescanWindow` already applies to `since`; `date_match_inputs_changed` is stamped from the same merge clock as `date_modified_canonical`, so the window covers it. Update the function's doc comment. EPSS path unchanged (design 7.1).

**Existing fixture in scope:** `ageCorpus` (`internal/alert/watchlist_cve_test.go:151-160`) moves `date_modified_canonical` and `date_epss_updated` back an hour so tests can prove an unchanged CVE is outside batch selection. After this change a CVE with a recent `date_match_inputs_changed` is selected anyway, so those tests could pass through the new branch while their own mechanism is broken. Add `date_match_inputs_changed = now() - interval '1 hour'` to its `UPDATE` for every row, and update the comment above it. Its callers (`late_binding_test.go`, `reopen_event_test.go`, `resolution_notification_test.go`, `retracted_cve_test.go`, `watchlist_cve_test.go`) must pass unchanged.

**Pitfall gate:** this commit touches the evaluator again. Run `/pitfall-check` on `internal/alert/evaluator.go`, `internal/merge/pipeline.go`, `internal/merge/match_inputs.go` and `internal/ingest/handler.go` before committing.

### Task 5.6: Re-check integration tests

**Files:** Create `internal/alert/match_inputs_recheck_test.go` (package `alert_test`, ABOUTME header). Each case ingests with `merge.Ingest`, reads `tdb.GetCVEChangeHashes` before and after, and calls `EvaluateRealtime` only when they differ — the handler's rule, whose own branching Task 5.4 unit-tests. The test asserts on that comparison too, so "realtime ran" is observed, not assumed.

**Cases (design section 12, "Re-check signal"):**
- A CNA product change alone (`n/a` → `Node.js`) runs realtime evaluation without moving `material_hash` or `date_modified_canonical`; the Node rule creates one event; an unrelated rule (`severity eq high`) that already had an event at this hash gets no new event and no new notification (assert with `mockDispatcher` Fanout count).
- A vulnerable-flag flip (`false` → `true`) on a `nodejs:node.js` match: same, one event.
- When realtime evaluation is skipped (ingest without calling `EvaluateRealtime`), the next `EvaluateBatch` evaluates the CVE through the `date_match_inputs_changed` branch and creates the event. Isolate the branch: run `EvaluateBatch` once first so the cursor is non-zero (a zero cursor scans everything), age the corpus with the Task 5.5 `ageCorpus` (which moves `date_modified_canonical` outside the rescan window), then make the CNA-only change so only `date_match_inputs_changed` is recent, and assert before the batch run that `date_modified_canonical` is older than the cursor minus two minutes. Falsification probe, once, before committing: copy `internal/alert/evaluator.go` to the session scratchpad, delete the second `UNION` arm, confirm this test fails, copy the saved file back with `cp` (which gives it a new modification time), confirm `git diff internal/alert/evaluator.go` shows Task 5.5's change intact, and rerun the test green. Do not restore with `git checkout`: Task 5.5's change may not be committed yet, and a checkout would discard it.
- A case-only difference between the MITRE and NVD copies does not change `match_inputs_hash` (no realtime run; assert `date_match_inputs_changed` unchanged).
- A CVE with an existing event whose stored `match_inputs_hash` is NULL is re-checked once on its next merge and sends no duplicate alert (event count and Fanout count unchanged).
- Late-binding: after a CVE ID move (follow `internal/alert/late_binding_test.go`), a product rule matches the new ID.

**Run:** `go test ./internal/alert/... -count=1 -run 'Recheck|LateBinding|Batch'`.

**Commit(s) (in order):** `feat(db): add match inputs re-check columns` (5.1–5.2), `feat(merge): compute match_inputs_hash beside material_hash` (5.3), `feat(alert): re-evaluate CVEs whose match inputs change` (5.4–5.6), each with its log entry.

**After Phase 5 group:** Review the batch once, from a perspective the individual tasks did not apply (here: concurrency and clocks — two merges of one CVE, the advisory lock, the rescan window, and a realtime failure followed by a batch run). Run further rounds only while the previous round produced material findings; stop when one produces none. A round run to reach a count, after findings have stopped, manufactures them — and a manufactured finding is the same defect as a suppressed one.

---

## Phase 6 — PLAN.md, reviews, full suite, PR

**Execution Status:** ✅ COMPLETE 2026-11-14 on branch `claude/lucid-moser-fef966` — 6.1 docs `2a49cdb`; 6.2 `/plan-check` all MATCH-2 markers met; 6.3 code review (no critical or important findings) and security review, fixes `0afb1dc`, `7e521af`, `d0e13d5`, `85baca7`, `d63337f`; 6.4 lint clean and full suite passed at `4b65c2f`; PR to `dev`: [scarson/CVErt-Ops#244](https://github.com/scarson/CVErt-Ops/pull/244), merged 2026-11-14 as `6103f0d`.

### Task 6.1: Documentation in the implementation PR

- **PLAN.md** (design section 11; edit each named section, keep surrounding style):
  - §10.1: add `affected.cpe_product` (CPE `vendor:product`; NVD vulnerable CPE rows and CNA names through the version check's name table), and that `affected.ecosystem` and `affected.package` are matched on one package row under `and`.
  - §10.2: `affected.package` takes `eq` and `in`, compared after package-name folding; `affected.cpe_product` joins the selective constraints for regex rules; the limits (50 product values, 100 conditions), the empty-`in` error on the new operators, and lists bound as one array parameter; ecosystems are compared exactly because rule and stored values are both canonical names (clarifies the case-insensitive `eq` line).
  - §10.5: the correlation change ships without a `dsl_version` bump (design 15.2).
  - §5.3: CNA product names and NVD vulnerable flags are match inputs outside `material_hash`. §10.3: the re-check signal (`match_inputs_hash`, `date_match_inputs_changed`) as a realtime trigger and a second batch cursor condition.
  - Appendix A: the two `cves` columns and the index; `cve_cpe_matches` and `cve_cna_affected` are read by alert rules.
- **Version check design** `dev/plans/2026-11-08-version-check-endpoint-design.md` section 4.5: an amendment line under the table: the Node row gains `node.js` / `node.js` and `the node.js project` / `node.js`, and the other-product boundary is an ASCII letter or digit, both from MATCH-2 (`dev/plans/2026-11-13-product-match-rules-design.md` sections 3.4 and 5.1); neither changes a stored answer on the kept ingest.
- **CLI/MCP seam:** check whether any CLI or MCP code that lists DSL fields or calls the validate endpoint exists on `dev` (`grep -rn "alert-rules/validate\|affected.package" cmd internal --include=*.go`, excluding `internal/alert` and `internal/api`). If it exists, describe the new field, operators, limits and the never-matching error there; if not, record under Discoveries that the CLI/MCP design (`dev/plans/2026-11-13-api-client-cli-and-mcp-server-design.md`) must carry them when built.
- **Implementation log:** the per-commit entries already exist; add a closing entry summarising measurements (link the results file) and review outcomes.

**Commit:** `docs: record product conditions and the re-check signal in PLAN.md` + log entry.

### Task 6.2: `/plan-check` against PLAN.md §10

Invoke `/plan-check` for PLAN.md §10 (and §5.3 for the re-check signal). Every "MUST"/"Required" marker it reports as unmet is fixed or taken to Sam with the evidence; none is dropped.

### Task 6.3: Code review

Invoke `superpowers:requesting-code-review` on the branch diff against `origin/dev` (three-dot: `git diff origin/dev...HEAD`). Also run the `security-review` skill: this work adds a public-API input (rule values reaching SQL as parameters) on a security product. Handle findings with `superpowers:receiving-code-review`.

### Task 6.4: Full suite and PR

1. `golangci-lint run --allow-parallel-runners ./...`
2. `go test ./... -count=1 -timeout=600s 2>&1 | tee test-run.log` (required before merging to `dev`). Read the log for failures; do not rerun without a change.
3. `git diff origin/dev...HEAD --stat` — confirm no unexpected deletions.
4. Push, open the PR to `dev` with the measurements table and the deviation list in the description; merge when review and CI are clean (Sam's standing instruction: land instructed work). Record PR and merge SHA in this plan (Living Document Contract).

---

## Dependencies and order

Strictly sequential: Phase 1 → 2 → 3 → 4 (gate) → 5 → 6. Phase 5's merge and migration work (Tasks 5.1–5.3) touches no file Phases 2–3 touch and could run in parallel in a second worktree, but Task 5.5 edits `internal/alert/evaluator.go`, which Task 2.2 also edits, and the Phase 4 gate may change the rule limits Phase 5's tests depend on. Keep one worktree and one writer.

## Out of scope (design section 14 and deferred-features section 12)

Version conditions (MATCH-3); `neq`/`not_in` on `affected.cpe_product`; CNA `package_key` in package rules; CNA-supplied CPEs; a watchlist product item; the name-table re-check step (built with the first table edit that changes a match; Task 1.3's digest test forces it); showing CNA rows on the CVE page; any SPA change.
