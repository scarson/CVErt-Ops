# Independent review, round 2: product conditions in alert rules (MATCH-2) design

Reviewed document: the round 2 snapshot of `dev/plans/2026-11-13-product-match-rules-design.md` (no snapshot ref was supplied).
Reviewer: independent all-lens reviewer, cold read. Code checked at the worktree `claude/match2-design-e1e345` (HEAD 39a4a13). No database was queried.

Findings are ranked most severe first. Each lists the lenses it belongs to; per-lens lines follow the list.

---

## Ranked findings

### R1 — No bound on a rule's total product terms: bind-parameter limit and per-CVE planning cost inside ingest

- **Lenses:** failure modes; unstated assumptions; seams & contracts; downstream readiness (pitfall DB-12)
- **Anchor:** §3.2 "`eq` and `in`. `in` takes 1 to 50 values."; §5.1 "**Ranges and names as `OR`-ed predicates, not a join to `unnest()` arrays.**"; §5.1 "passed as parameters, never concatenated"
- **Claim:** The 50-value cap applies per condition, but nothing bounds the number of conditions in a rule, so nothing bounds the number of OR-ed predicates or bind parameters a rule compiles to. A rule with enough product conditions exceeds PostgreSQL's 65,535 bind-parameter limit and fails on every evaluation. Below that limit, planning thousands of OR-ed predicates is paid on every realtime evaluation, which runs synchronously in the feed ingest loop, for every active rule of every org.
- **Evidence:**
  - `dsl.Parse` checks only that `conditions` is non-empty (`internal/alert/dsl/parser.go`); `Validate` has no condition-count check (`internal/alert/dsl/validator.go`). The only bound is the 1 MiB request limit.
  - Per value, the design emits one range per part (3) per CPE spelling, each with three parameters (`$lo`, `$hi`, `$prefix`), and one term per CNA name with four parameters (`$v`, `$p`, `$fullv`, `$fullp`) (§5.1 SQL). For `nodejs:node.js` the table gives 2 CPE spellings (6 ranges, 18 parameters) and, after `NamesFor` with the two added names, about 5 distinct CNA names (about 20 parameters): roughly 38 parameters per value, about 1,900 per 50-value condition. About 35 such conditions exceed 65,535. `f5:nginx` has 3 spellings (27 range parameters) before its names.
  - `implementation-pitfalls.md` DB-12 ("Dynamic `IN` Clause Overflows Postgres 65,535 Parameter Limit") prescribes one array parameter for user-supplied lists. The design deliberately chose OR-ed per-value parameters for plan quality (§5.1), so it needs its own bound.
  - Realtime evaluation is synchronous: `internal/ingest/handler.go:219-220` calls `eval.EvaluateRealtime` inside the per-patch loop, and `EvaluateRealtime` evaluates every active rule (`internal/alert/evaluator.go:92-117`). A slow rule slows ingestion of every feed. A rule whose query errors makes the batch path hold its cursor for all rules for up to 30 runs, then repeat (`batchMaxHeldRuns`, evaluator.go:173-176, 283-292).
  - §13 measures "an `in` of 50 ... including planning time" for dry-run only; the realtime row measured is a single `linux:linux_kernel` value (§5.3, §13).
- **Axes:** objective (no bound exists in the design or the code; the parameter arithmetic follows from §5.1). Remedy is a choice: a per-rule cap on product values or expanded terms enforced by the validator, de-duplication of values, or a parameter count check at compile time.

### R2 — Activation scan duration against the 15-minute zombie sweep is unmeasured

- **Lenses:** failure modes; unstated assumptions; downstream readiness (pitfall NOTIFY-5)
- **Anchor:** §5.2 table "`alert.Evaluator.queryCandidates` (realtime, batch, EPSS, activation) | its own list"; §13 "the section 5.3 rows for realtime ..., batch (5,000 IDs) and dry-run ..."
- **Claim:** The design changes the query every activation page runs but never measures a whole activation scan. An activation that runs past 15 minutes is marked a zombie: the rule goes to `error` and the job to `failed`, while the worker keeps running.
- **Evidence:**
  - Activation pages the whole corpus in 1,000-ID pages (`activationBatch = 1000`, evaluator.go:28, 325-343): about 2,600 queries on 2.6 million CVEs.
  - `SweepZombieActivations` fails jobs with `locked_at < now() - interval '15 minutes'` (evaluator.go:372-407). `locked_at` is set once at claim (`internal/store/queries/jobs.sql:8`); no heartbeat refreshes it (grep for `locked_at` outside users/auth finds only the claim, the release and the sweep). `implementation-pitfalls.md` NOTIFY-5 describes this sweep.
  - Budget: 900 s / 2,600 pages ≈ 346 ms per page, including event inserts. §5.3's batch row for `linux:linux_kernel` is 447 ms for 5,000 IDs; there is no row for 1,000-ID pages, for a 50-value `in`, or for a package condition with no ecosystem.
  - §12's "Same answer on every path" test runs on the 71-record seeded corpus, so it says nothing about duration.
- **Axes:** objective that it is unmeasured; whether it breaches 15 minutes is contestable until measured. Remedy is determinate (add a full activation scan of the heaviest shapes to §13 with the 15-minute budget as the threshold); a heartbeat is a separate choice.

### R3 — The material hash change moves every CVE's hash unless the new field is omitted when empty, and the cost section counts only notifications

- **Lenses:** failure modes; change & reversibility; downstream readiness (pitfall ARCH-47)
- **Anchor:** §7 "`MaterialFields` gains `affected_products`: the sorted, distinct pairs of CNA vendor and product"; "Cost: the hash of every CVE with CNA rows (405,809 of about 2.6 million) changes on its next merge."
- **Claim:** The 405,809 figure holds only if the new key is left out of the canonical JSON when a CVE has no CNA rows. The design does not say so, and the existing convention does the opposite. The cost section also leaves out the ingest-time cost of the hash change.
- **Evidence:**
  - `ComputeMaterialHash` marshals the whole struct and turns every nil slice into `[]` "so JCS produces \"[]\" not \"null\"" (`internal/merge/hash.go:76-85`); no existing slice field uses `omitempty`. A new `affected_products` field handled the same way adds `"affected_products":[]` to every CVE's canonical JSON, so all ~2.6 million hashes change, each firing again for every rule it matches.
  - The sort comparator is not stated. "Sorted ... pairs" needs a comparison on vendor, then product; `implementation-pitfalls.md` ARCH-47 ("An Array Sort Before Hashing Must Compare Every Hashed Field") is the documented failure.
  - Each redelivered CVE whose hash moves runs realtime evaluation of every active rule, synchronously in the ingest loop (`internal/ingest/handler.go:219-220`), and moves `date_modified_canonical`, which enlarges batch candidate sets. §7 notes "an OSV backfill would deliver most of them at once" but costs only the extra notifications, not the slower ingestion.
- **Axes:** the serialization point is objective. The remedy is determinate: state `omitempty` (or accept and restate the 2.6 million figure), state the comparator, and add the ingest-time cost to §7 and open question 2.

### R4 — The material hash recommendation weighs only "hash it" against "accept the gap"; a separate trigger for match inputs is not considered

- **Lenses:** alternatives & rationale; simplicity & proportionality
- **Anchor:** §7 "**Recommendation: add the CNA product identity to `material_hash`.**"; §3.5 step 3 "closing it would put the vulnerable flag into the hash, which changes the hash of every NVD-analysed CVE"
- **Claim:** Both gaps (CNA product change, §3.5 step 4; vulnerable-flag flip, §3.5 step 3) come from match inputs that are not material. An obvious alternative is not recorded: a change signal for those inputs that schedules evaluation (realtime trigger and batch candidacy) without changing the dedup key. `alert_events` is unique on `(org_id, rule_id, cve_id, material_hash)`, so a CVE that newly matches fires once, and CVEs already alerted do not fire again. This would close both gaps without the corpus-wide re-fire that §7 accepts and §3.5 step 3 rejects.
- **Evidence:** the ingest handler triggers realtime on a hash difference only (`handler.go:210-220`); `date_modified_canonical` moves only when the hash changes (`pipeline.go:178-179` comment, used by `getCVEsModifiedSince`). The alternative costs a second signal (a column or timestamp) and changes to those two call sites. It may lose on its own merits, for example by changing what `date_modified_canonical` means to saved-search ordering, but the design does not show it was weighed.
- **Axes:** contestable; the remedy is a choice (record and reject, or adopt).

### R5 — The exact package match, as described, cannot use the index §6 says it uses, and the correlated package SQL is never given

- **Lenses:** downstream readiness; seams & contracts; unstated assumptions
- **Anchor:** §4.1 "`ecosystem.FoldedNameSQL(cap.ecosystem, cap.package_name)` against the same expression applied to the value with the row's ecosystem"; §6 "`cve_affected_packages_check_idx` on `(ecosystem, folded name)` | Exact package match with an ecosystem"; §5.3 "Dry-run, `Debian` and `openssl` correlated | 0.90 s"
- **Claim:** The SQL as §4.1 describes it puts a row-dependent expression on the right-hand side, which no index can serve. The ecosystem predicate the compiler emits today cannot use this index either. The plan author has to invent the correlated group's SQL, and the shape behind the measured 0.90 s is not in the repository.
- **Evidence:**
  - The index is `(ecosystem, CASE WHEN ecosystem = 'PyPI' THEN regexp_replace(lower(package_name), ...) ELSE lower(package_name) END)` on the raw `ecosystem` column (`migrations/000059_check_lookups.up.sql`). `FoldedNameSQL("cap.ecosystem", $v)` expands to `CASE WHEN cap.ecosystem = 'PyPI' THEN ... lower($v) ...` (`internal/ecosystem/ecosystem.go:119-121`): it references the row, so it is a filter, not an index qualifier. The version check reaches the index by folding in Go for each ecosystem and comparing a constant: `q.ecosystem = k.eco AND <folded> = k.name` (`internal/store/check.go:132-141`, `keys.go:139-143`).
  - Today's ecosystem condition is `lower(cap.ecosystem) LIKE ANY(['debian','debian:%'])` (`compiler.go:315-329`), which cannot use an index on raw `ecosystem`. §4.2's "a Debian row (any release)" needs `ecosystem = 'Debian' OR ecosystem` in a range from `'Debian:'` to `'Debian;'`, which works because `ecosystem.Valid` admits only canonical-case base names. The design does not say so.
  - §5.1 shows only the product branch's SQL. §5.3 says "The measurement queries are kept with the session notes, not in the repository".
- **Axes:** objective (the index definition and the expression text settle it). The remedy is determinate: give the correlated group's SQL (expansion for each ecosystem, a range for a prefix ecosystem, the name folded in Go) and keep the measured queries with the plan.

### R6 — Nobody owns the index expressions and key builders the rule SQL depends on

- **Lenses:** seams & contracts; downstream readiness
- **Anchor:** §3.4 "The table, `ProductRef` and the CPE value checks move to a new package `internal/product`"; §5.1 "Ranges, prefixes and names are built in Go from `internal/product` (as `check.CPEKeyFor` and `cnaNameKey` build them today)"
- **Claim:** The move list in §3.4 leaves out what the rule SQL needs most: the key builders and the exact index expressions. The DSL compiler cannot reach the expressions where they live now, so the plan must either duplicate them or move them, and the design says neither.
- **Evidence:**
  - `CPEKeyFor`, `cnaNameKey`, `cutRunes`, `nextPrefix`, `CPEKeyRunes` and `cnaNameRunes` are in `internal/check/keys.go`. The expressions `left(%s, 512) COLLATE "C"` and `left(lower(col), 256) COLLATE "C"` are unexported helpers in `internal/store/check.go:43-45, 107-109`.
  - `internal/alert/dsl` cannot import `internal/store`, because `internal/store/dsl_executor.go` imports `dsl`.
  - If the compiler's text differs from the migration's index expression even slightly, the planner falls back to a sequential scan with no error. §5.3 shows the cost of the wrong plan: 7.7 to 13.9 s, and over 60 s under `or`. Duplicating the text also runs against the project rule on duplication.
- **Axes:** objective (the import direction and the move list are facts). The remedy is determinate: name `internal/product` (or another package that both `store` and `dsl` can import) as the single owner of the key builders and the index-expression strings.

### R7 — The rule's value checks contradict the stated parity with the version check

- **Lenses:** requirements trace (internal consistency); downstream readiness
- **Anchor:** §3.1 "Each component must be a literal: not empty, not `*` or `-`, and containing no unescaped `*` or `?`."; §3.1 "so a product that one accepts the other also accepts"
- **Claim:** The design adds a rule that the check does not have, and leaves out one that it does, while claiming the two accept the same products.
- **Evidence:**
  - Unescaped wildcards: the check accepts `*` and `?` inside a vendor or product. `literalCPEValue` refuses only `""`, `"*"` and `"-"`, and `escapedAsCPERequires` explicitly allows `*` and `?` (`internal/check/input.go:248-267`). The design refuses them.
  - Printable ASCII: `parseCPE` refuses any character outside printable ASCII before lower-casing, because "Go's strings.ToLower and PostgreSQL's lower() ... can disagree outside ASCII" (`input.go:203-209`). That check is inline in `parseCPE`, not in the four functions §3.1 names, and §3.1 and §8 do not list it. For example, KELVIN SIGN U+212A lower-cases in Go to ASCII `k` and then passes `escapedAsCPERequires`. An escaped control character (`\` followed by 0x01) also passes the named functions, while the check refuses it.
  - So either the check's behaviour changes, which the design does not state, or the parity claim is false.
- **Axes:** objective. The remedy is a choice of which rule set wins, followed by stating that in §3.1 and §8.

### R8 — Package-with-package correlation is not requested, makes "affects both" impossible to express, and the stated workaround is wrong

- **Lenses:** requirements trace (unrequested element); simplicity & proportionality; alternatives & rationale
- **Anchor:** §4.2 "Two package conditions in one `and` rule must also hold on one row, so `{affected.package eq a, affected.package eq b}` matches nothing; ... "a CVE that affects both" needs two rules."
- **Claim:** Requirement 2 (§1) correlates `affected.ecosystem` with `affected.package`. The design also correlates package conditions with each other, and ecosystem `eq`/`in` conditions with each other (`{ecosystem eq npm, ecosystem eq PyPI}` now matches nothing). This turns rules that mean something today into rules that never match. The workaround the design offers does not work: two rules each alert for a CVE that affects either package, and nothing combines rules with AND, so "affects both a and b" can no longer be expressed at all.
- **Evidence:** §1 requirement 2 text; §4.2 quoted above. §8 has no warning row for an `and` rule whose correlated group can never hold on one row, so such a rule saves silently.
- **Axes:** the workaround claim is objectively wrong; whether to correlate package with package is contestable. The remedy is a choice: correlate each package condition only with the ecosystem conditions, or keep the design and refuse or warn about the impossible group in §8, and correct the workaround text.

### R9 — `NOT IN` for `affected.ecosystem` `neq`/`not_in`: NULL-safety is argued, plan shape is not

- **Lenses:** failure modes; alternatives & rationale; unstated assumptions
- **Anchor:** §5.1 "`neq` and `not_in` on `affected.ecosystem` compile to `cves.cve_id NOT IN (...)`; `cve_id` is `NOT NULL` in every child table, so `NOT IN` cannot meet a NULL."
- **Claim:** The design argues only that `NOT IN` is correct with no NULLs; it does not show it is fast. In PostgreSQL, `NOT IN (subquery)` does not become an anti-join. It runs as a hashed SubPlan only when the estimated subquery result fits in hash memory; otherwise it is a plain SubPlan probed once per outer row. On the paths that pass no candidate IDs (dry-run, saved search, AI search), the subquery is every CVE with a row in the ecosystem, which for Debian- or Ubuntu-sized ecosystems is a large part of 2.6 million CVEs. `NOT EXISTS` has the same meaning here and plans as an anti-join; it is not mentioned. §5.3 and §13 have no `neq` row.
- **Evidence:** the §5.3 table has no `neq` or `not_in` row. Probe for the runner, on the kept ingest:
  `EXPLAIN SELECT cves.cve_id FROM cves WHERE cves.cve_id NOT IN (SELECT cve_id FROM cve_affected_packages WHERE ecosystem = 'Debian' OR (ecosystem >= 'Debian:' AND ecosystem < 'Debian;')) LIMIT 5001;`
  Check whether the plan shows "hashed SubPlan" or a plain "SubPlan", and repeat with the `NOT EXISTS` form.
- **Axes:** contestable (it depends on `work_mem` and the counts); the remedy is determinate (measure, or use `NOT EXISTS`).

### R10 — The "other products" exclusion exists twice, in Go for the check and in SQL for the rule, with no parity test and no owner

- **Lenses:** seams & contracts; downstream readiness (testing-pitfalls §2, §9)
- **Anchor:** §5.1 "This is the rule `check.isOtherProduct` applies today: `.NET Framework 4.8` is excluded from `microsoft:.net`, `.NET FrameworkExtensions` is not."
- **Claim:** The check filters rows in Go with `isOtherProduct`, which uses `strings.ToLower` and `unicode.IsLetter`/`unicode.IsDigit` (`internal/check/names.go:111-119`). The rule repeats the rule in SQL, which uses `lower()` and a SQL character class. The two implementations differ outside ASCII. The design names no owner for the SQL form and no test that the two agree.
- **Evidence:** `testing-pitfalls.md` §2 ("Case-sensitivity divergence between SQL and application layers") and §9 ("Behavioral parity between alternate code paths") describe this class of bug. §12 tests the SQL path with ASCII examples only. §3.4's "the table's tests cover both callers" covers the table's data, not the exclusion logic.
- **Axes:** severity is contestable (the current names are ASCII); the remedy is determinate (one owner in `internal/product`, plus a parity test that runs both forms on the same vendor and product strings, including non-ASCII ones).

### R11 — Measurements do not cover the shapes the claims rest on

- **Lenses:** unstated assumptions; downstream readiness
- **Anchor:** §5.1 "Their dry-run gets faster: `npm` and `contains lodash` on one row takes 0.88 s, against 4.7 s for today's `contains lodash` alone."; §5.2 table "`store.ExecuteDSLQuery` (saved searches, AI search) | none"; §5.3 "The measurement queries are kept with the session notes, not in the repository"
- **Claim:**
  - (a) "Gets faster" generalizes from the correlated case. Existing rules with `affected.package contains X` and no ecosystem condition, or under `or`, also move to the CVE-set form and are not measured. The closest measured case, `eq` with no ecosystem, takes 10.5 s, against 4.7 s today for `contains`.
  - (b) `ExecuteDSLQuery` runs a different shape: `ORDER BY cves.date_modified_canonical DESC, cves.cve_id DESC LIMIT limit+1` with a keyset cursor and no candidate cap (`internal/store/dsl_executor.go:143-157`). Every dry-run row in §5.3 is the evaluator's unordered `LIMIT 5001` (evaluator.go:610-623), and §13 does not add the saved-search shape.
  - (c) The SQL behind the numbers is not kept with the design, so a plan author cannot reproduce the plans §5.1 depends on.
  - (d) All numbers are from PostgreSQL 18. The project CLAUDE.md says "PostgreSQL 15+", though compose and testcontainers pin 18. This is minor; the design does not say whether 15 to 17 are in scope.
- **Axes:** (a) and (b) are objective gaps; (d) is minor. The remedy is determinate: add those rows to §13 and keep the queries with the plan.

### R12 — The 10.5 s shape sits at 75% of the 14 s statement timeout, and the only guard is a warning that AI search ignores

- **Lenses:** failure modes
- **Anchor:** §5.3 "Dry-run, `affected.package eq openssl`, no ecosystem | not applicable | 10.5 s"; §8 last row (warning)
- **Claim:** Dry-run runs with the connection default of 14 s (`DryRun` calls `bypassTx(ctx, 0, ...)`, evaluator.go:430). Saved and AI search use the same default. At 10.5 s on today's corpus, growth or a busy database will push this shape past the timeout, after which every dry-run and every saved-search page for it fails. AI search validates its generated rules but acts only on blocking errors (`internal/api/ai.go:180-181`), so the warning never reaches anyone, and the prompt will list `eq` for `affected.package` (§10).
- **Axes:** contestable (how much headroom is enough). The remedy is a choice: accept it and record the headroom, refuse `eq`/`in` without an ecosystem outside the paths that pass candidate IDs, or give dry-run the long timeout.

### R13 — §4.3's account of narrowed rules is incomplete, and the PLAN.md change list omits two sections the design departs from

- **Lenses:** change & reversibility; downstream readiness
- **Anchor:** §4.3 "On its next evaluation of a CVE that no longer matches, the batch path resolves the open event and sends a resolution notification"; §11 PLAN.md list
- **Claim:**
  - A CVE is evaluated again only when it changes materially, or when the realtime path runs for it. Realtime also resolves: `EvaluateRealtime` calls `evaluateRule` with `suppressResolution=false` (evaluator.go:105), so "the batch path" is inaccurate. Open events from the old, uncorrelated reading therefore stay open indefinitely and resolve at unrelated later times. If §7 ships too, they resolve in bulk during the redelivery wave, mixed with the re-fires.
  - §11 does not amend PLAN.md §10.5 (DSL versioning), the policy §4.3 knowingly departs from. It also does not add `affected.cpe_product` to §10.2's list of selective constraints for regex rules, which §8 changes through `selectiveFields`.
- **Axes:** the PLAN.md omissions are objective with a determinate fix. How to handle stale open events is a choice: accept and state it, or run a one-time re-evaluation of each affected rule's open events.

### R14 — Changes to the name table reach only CVEs that change afterwards

- **Lenses:** change & reversibility
- **Anchor:** §3.4 "Adding a name to the table changes what existing rules and checks match, from their next evaluation"
- **Claim:** For rules, "next evaluation" of a CVE happens only when that CVE next changes materially. A name added to fix a missed spelling never alerts for CVEs already ingested, and a wrong name that is removed leaves its open events until those CVEs change. Activation baselines are not re-run. The design states no back-fill or re-activation step for table edits, and §3.4 reads as if the effect were immediate.
- **Axes:** objective; the remedy is a choice (state the limitation, or re-activate affected rules on a table change).

### R15 — Some references to real artifacts give no location

- **Lenses:** downstream readiness
- **Anchor:** §2 "the complete ingest kept from the version check plan's Phase 2"; §3.4 "That table is the version check design's section 4.5"; §14 "(version check plan, Phase 4 notes)"
- **Claim:** Each reference describes what it points at, but none gives a path, so a reader cannot find the version check plan, the version check design or the Phase 4 notes without searching. The 3,905 and 573 counts in §14 rest on the Phase 4 notes.
- **Axes:** objective; the remedy is determinate (add the repository paths).

---

## Per-lens results

**Lens: requirements trace.** Requirements completeness unverifiable — unpinned (§1 status "unconfirmed"; standing finding). Internal consistency only:
- R7: §3.1 claims parity with the version check and contradicts it.
- R8: correlation is extended beyond requirement 2; this element is unrequested.
- Requirements 4 and 5 are narrowed (watchlists deferred; the acceptance example replaced), but both are marked open (questions 3 and 1), so they are not silent.

Findings: R7, R8, plus the standing "requirements completeness unverifiable — unpinned".

**Lens: simplicity & proportionality.** Findings: R8 (package-with-package correlation adds meaning that nothing requests and removes expressiveness), R4 (a cheaper option than a corpus-wide hash change was not weighed). The set form with candidate IDs inside the set, and `CompiledRule.Where`, are paid for by the §5.3 numbers; no finding there.

**Lens: seams & contracts.** Units and boundaries:
- `internal/product` (name table, `ProductRef`, value checks) is imported by `internal/check` and `internal/alert/dsl`.
- `dsl` hands `CompiledRule.Where` to the evaluator and to `store.ExecuteDSLQuery`.
- `internal/merge` supplies the hash that the ingest handler compares to trigger realtime evaluation.
- Migrations define the index expressions that the compiler must reproduce.

Findings: R6 (the index-expression and key-builder contract has no owner across the import cycle), R10 (the other-products rule exists in two languages with no owner of parity), R5 (the correlated group's contract with `cve_affected_packages_check_idx` is unstated), R1 (no contract on rule size between validator and compiler).

**Lens: failure modes.** Findings: R1, R2, R3, R9, R12, R13. Security: values reach SQL as parameters and are validated, and the table supplies the CNA names. The remaining hostile-input exposure is the size problem in R1, where any member who can save a rule can slow ingestion for every org. No separate injection finding.

**Lens: unstated assumptions.** Findings: R1 (rule size), R2 (activation finishes inside the zombie window), R9 (`NOT IN` stays a hashed subplan), R11 (the measured shapes stand for the unmeasured ones; PostgreSQL 18 only), R5 (an exact-name index path exists for the described SQL).

**Lens: alternatives & rationale.** Findings: R4 (a separate trigger for non-material match inputs), R9 (`NOT EXISTS`), R8 (correlating only ecosystem with package).

**Lens: change & reversibility.** Findings: R3 (the reach of the hash change and its revert cost depend on an unstated serialization), R13 (stale open events; PLAN.md §10.5 not amended), R14 (name-table edits are not back-filled).

**Lens: downstream readiness.** Findings: R5, R6, R7, R11, R15, and R3 (`omitempty` and the comparator unstated). Pitfalls docs read (`dev/implementation-pitfalls.md`, `dev/testing-pitfalls.md`). Planned elements that walk into documented pitfalls:
- DB-12 (bind-parameter limit): R1.
- NOTIFY-5 (zombie activation sweep): R2.
- ARCH-47 (hash sort must compare every field): R3.
- ARCH-21 (statement timeout): R12.
- testing-pitfalls §2 (SQL and application layers disagree) and §9 (parity between alternate code paths): R10.
