# Independent review, round 6: product conditions and correlated package conditions in alert rules (MATCH-2)

Cold read of the snapshot at `C:\Users\Sam\AppData\Local\Temp\claude\fca09f7c163a3f5b\02f52364-7dc0-4cc4-9bd7-c5bcaa70a3b5\scratchpad\round6-snapshot.md`, checked against the work tree at `C:\Users\Sam\Code\CVErt-Ops\.claude\worktrees\match2-design-e1e345`. No database queries were run (out of bounds for this review); where a claim needs one, the probe is given.

Findings are ranked most severe first. IDs are local to this report.

## Findings

### R1 · downstream readiness, requirements trace (internal consistency)
- **Anchor:** §12 Tests, "Integration with `testutil.SeedCorpus`": "A rule `{affected.cpe_product eq fastify:fastify, severity in [critical, high, medium]}` matches CVE-2026-107832 with no NVD row; this is the seeded form of the acceptance case."
- **Claim:** The seeded acceptance test cannot pass as written. CVE-2026-107832's only severity in the seeded fixtures is LOW, which is not in the rule's list.
- **Evidence:** In `internal/feed/nvd/testdata/golden/page-001.json`, CVE-2026-107832 has one CVSS metric: `cvssMetricV31`, source `ce714d77-...` (the CNA), `Secondary`, base score 3.7, `LOW`. The MITRE golden record (`internal/feed/mitre/testdata/golden/cvelistV5.zip`, `cves/2026/107xxx/CVE-2026-107832.json`) carries the same `cvssV3_1` 3.7 `LOW`, and its CISA ADP container has only SSVC. No other golden fixture (GHSA, OSV and the rest) mentions the CVE or `fastify`. So the resolved `cves.severity` is `LOW`, and `severity in [critical, high, medium]` excludes it. The section says "The test asserts the severity it relies on", so that assertion would fail first. The §1 acceptance rule uses `[critical, high]`, so the seeded form also differs from the requirement's rule.
- **Axes:** objective. Remedy is a choice: add `low` to the rule, drop the severity condition, or seed a different CNA-only CVE that has a medium-or-higher severity.

### R2 · seams & contracts, failure modes, change & reversibility
- **Anchor:** §8 Validation and messages: "Errors stop a save; warnings are returned with a valid rule." Relied on in §4.2 ("The validator warns about that shape (section 8)") and §5.3 ("The validator warns about it (section 8)").
- **Claim:** The API returns warnings only from `POST .../alert-rules/validate`. Create and update return none, and saved searches and AI search drop them. So the warnings this design uses as mitigations never reach a caller who saves a rule directly, and they cannot reach a rule that is already stored.
- **Evidence:** `internal/api/alert_rules.go` `createAlertRuleHandler` calls `parseDSL` and checks only `hasBlockingErrors(valErrs)`. It then writes `alertRuleToEntry(*row)`, which has no warnings field. Only `validateAlertRuleHandler` (lines 616–668) splits out `Warnings`. `internal/api/saved_searches.go` `validateDSL` and `internal/api/ai.go` line 181 both check only `hasBlockingErrors`. The cases this affects:
  - §4.2's shape `{ecosystem eq npm, ecosystem eq PyPI, package contains x}` "matches nothing" under the new compile rules. A rule saved in that shape matches nothing, and nothing tells the user.
  - Existing stored `and` rules of that shape (§4.3) go from matching to matching nothing when this ships. Their open events resolve with "no longer matches the rule's conditions", which reads as data change rather than rule breakage. Nothing re-runs `Validate` on stored rules, so no warning is ever produced for them. §4.3 describes narrowing but does not single out this matches-nothing case.
  - The no-ecosystem package warning and the unmapped-product warning are invisible on save for the same reason.
- **Axes:** objective (the §8 claim does not match the code). Remedy is a choice: return warnings from create and update, refuse the matches-nothing shape outright, or record that warnings appear only through `/validate` and list affected stored rules at deploy time.

### R3 · failure modes, simplicity & proportionality, downstream readiness (pitfall DB-12)
- **Anchor:** §3.2 Operators: "**At most 100 conditions per rule** ... so without a bound on conditions a rule could still pass PostgreSQL's 65,535-parameter limit inside the 1 MiB request limit ... With both limits, a rule's worst case is about 50 product values of about 40 parameters each plus 100 conditions of at most 4 each, under 3,000 parameters." Also: "Package names and ecosystem values ... are bound as arrays, one parameter per list, as the compiler binds `in` lists today".
- **Claim:** The parameter bound is wrong, so the 100-condition limit does not close the DB-12 hole it is meant to close. Today's compiler binds `in` lists for `kindString` and `kindEnum` fields (`cve_id`, `severity`) with one parameter per value, not as an array. A single condition can therefore exceed 65,535 parameters on its own.
- **Evidence:** `internal/alert/dsl/compiler.go` `setSQL` returns `sq.Eq{sqlExpr: vals}` for `in` and `sq.NotEq{sqlExpr: vals}` for `not_in`. Squirrel's `expr.go` (lines 185–196) turns a slice into `key IN (?,?,...)` with `Placeholders(valVal.Len())` and appends one argument per element. `cve_id` is `kindString` with `in` and no value-format or list-length check (`validator.go`, `kindString` branch). A body such as `{"field":"cve_id","operator":"in","value":["a","b",...]}` costs about 4 bytes per value, so the 1 MiB `middleware.RequestSize(1 << 20)` (`internal/api/server.go:235`) allows roughly 260,000 values in one condition. Only `affected.ecosystem` (`pq.Array(patterns)`) and `cwe_ids` are bound as arrays today. The "at most 4 each" figure and the claim about how `in` lists are bound today are both wrong. The design's own failure story (fail on every evaluation, hold the batch cursor) stays reachable with one condition. Measured against its stated purpose, the 100-condition limit costs code and removes no failure.
- **Axes:** objective. Remedy is a choice: bind every `in`/`not_in` list as one array parameter (`= ANY(?)`, as DB-12 prescribes), cap list length, or both. The 100-condition limit then needs a different justification or can be dropped.

### R4 · downstream readiness, failure modes, unstated assumptions
- **Anchor:** §5.1, package SQL: "`AND (cap.ecosystem = ANY($ecos1) OR cap.ecosystem LIKE ANY($releases1))   -- one line per eq/in ecosystem condition`" and the table cell "With an ecosystem condition naming exact values, the index serves `ecosystem = ANY` with `<folded name> = ANY`".
- **Claim:** The designed statement and the measured statement differ in the predicate that decides index use. The fast case (0.52 ms) was measured as `cap.ecosystem = 'npm' AND <folded> = 'lodash'`, with no release arm and no PyPI split (Appendix A). The design emits `OR cap.ecosystem LIKE ANY($releases)` for every `eq`/`in` ecosystem value, including `npm`, which takes no release suffix. An OR of an indexable `= ANY` with a non-indexable `LIKE ANY(array)` gives the leading column of `cve_affected_packages_check_idx` no usable qual. The design asserts index use for the array form without having measured it. §13 lists the measurement but expects it to use the index, and does not name the release arm as the risk.
- **Evidence:** `cve_affected_packages_check_idx` is `(ecosystem, <folded name>)` in the default collation (`migrations/000059_check_lookups.up.sql`). A btree cannot serve `LIKE ANY(text[])`, and a default-collation btree cannot serve LIKE prefixes even singly. `internal/ecosystem` already knows which names take a suffix (`takesSuffix`, unexported; `IsDistro`/`NeedsRelease` exported), so the release arm can be left out for `npm`, `PyPI`, `Go` and the like. On PostgreSQL 18, btree skip scan may hide the cost. On 15–17 it may not (see R11). This affects dry-run and saved searches; realtime, batch and activation are protected by the candidate filter.
- **Probe:** on the kept ingest, run `EXPLAIN (ANALYZE, COSTS OFF)` of the §5.1 package set with `$ecos1 = '{npm}'`, `$releases1 = '{npm:%}'`, `$names = '{lodash}'`, `$pypiNames = '{lodash}'` and no candidates, and compare it with the same statement without the `LIKE ANY` arm.
- **Axes:** contestable until probed. Remedy is mostly determinate: emit the release arm only for ecosystems that take a suffix, and measure the designed statement rather than a simplified one.

### R5 · unstated assumptions, seams & contracts, alternatives & rationale
- **Anchor:** §3.3 Sources: "**CNA:** a `cve_cna_affected` row whose vendor and product, in lower case, equal one of the product's CNA names ... Every stored copy is read". Compare "**NVD:** a `cve_cpe_matches` row with `vulnerable = true`".
- **Claim:** The NVD source is filtered to rows that assert the product is affected. The CNA source matches any row that names the product, including a CVE 5 entry that names the product only to say it is unaffected (`defaultStatus: unaffected` with no `affected` version). The design does not record this asymmetry. It also contradicts the design's own reason for sharing the name table ("a rule and a check of one product read the same CNA rows"): for such a row the version check concludes "no statement", while the rule fires.
- **Evidence:** `internal/check/cna.go` `readEntry`: "An entry that is wholly unaffected can condemn nothing ... `if e.Status == "unaffected" && len(e.Changes) == 0 { return reading{result: NoStatement} }`". `cve_cna_affected` stores `default_status` and `versions` (`migrations/000053_create_cve_version_ranges.up.sql`), so the data needed to filter exists. Some CNAs list products they consider unaffected in `affected[]`. §3.3's "fails towards telling the user" argument covers union across sources, not CNA rows that deny being affected.
- **Probe:** `SELECT count(*) FROM cve_cna_affected WHERE lower(coalesce(default_status,'')) <> 'affected' AND NOT jsonb_path_exists(versions, '$[*] ? (@.status != "unaffected")');` on the kept ingest, then the same restricted to the six table products.
- **Axes:** contestable (how many rows, and whether the noise matters). Remedy is a choice: filter out wholly-unaffected CNA entries, or keep them and record why.

### R6 · alternatives & rationale, downstream readiness (pitfall NOTIFY-2)
- **Anchor:** §3.5 step 3: "This gap is accepted: closing it would put the vulnerable flag into the hash, which changes the hash of every NVD-analysed CVE." Compare §7: "**Recommendation: add the CNA product identity to `material_hash`.** ... the hash of every CVE with CNA rows (405,809 of about 2.6 million) changes on its next merge."
- **Claim:** The reason given for rejecting the vulnerable-flag fix does not separate it from the recommended CNA fix. Both are a one-time move of a large share of corpus hashes. If one such wave is acceptable, both changes can share it at little extra cost. Instead, a known alerting gap is kept with "documented limitation" as the justification. That is the pattern pitfall NOTIFY-2 rejects for a security alerting product: "'Document the limitation' is not an acceptable resolution for a correctness failure in a security alerting system."
- **Evidence:** The two quoted passages. NOTIFY-2 in `dev/implementation-pitfalls.md`. A flip of `vulnerable` with the same criteria string decides whether a product rule matches (§3.3 reads only `vulnerable = true` rows), and no evaluation path sees the flip.
- **Axes:** contestable (how often NVD flips the flag without changing criteria). Remedy is a choice: add the flag to the same hash change, adopt §7's separate evaluation signal (which closes both), or keep the gap with a reason that survives comparison with §7.

### R7 · alternatives & rationale, change & reversibility
- **Anchor:** §7: "`MaterialFields` gains `affected_products` ... the distinct pairs of CNA vendor and product" and the alternative "a separate evaluation signal". Also §1.1: "Version conditions come later (requirement MATCH-3, not designed here)".
- **Claim:** §7's choice between hash and signal does not weigh the stated next step. Version conditions (MATCH-3) will match on CNA `versions` and on NVD match ranges, neither of which is a hash input (`internal/merge/pipeline.go`: "CPE match ranges and CNA affected entries. Neither is a material_hash input"). The pair-only hash covers neither. MATCH-3 will then face the same choice again: either a second corpus-wide hash move with another re-fire wave, or the separate signal after all. Either way, the cost now recommended (405,809 re-fires and modified CVEs) may be paid twice. The rationale "one mechanism" holds only if no later field needs the same treatment.
- **Evidence:** The quoted passages and the pipeline comment.
- **Axes:** contestable. Remedy is a choice: state that MATCH-3 is expected to extend the hash again and accept the second wave, or prefer the signal now because MATCH-3 needs it.

### R8 · unstated assumptions, failure modes
- **Anchor:** §5.1 "`cves.cve_id IN ( SELECT ... UNION ALL SELECT ... )`"; §5.3 rows "Dry-run, `nodejs:node.js` `or` `in_cisa_kev` | 1.32 s"; §13 "a rule of 50 product values (table-mapped and unmapped) and 100 conditions, realtime against one CVE and dry-run".
- **Claim:** Under `logic: or`, PostgreSQL cannot turn `IN (subquery)` into a semi-join. It plans a SubPlan, which is hashed only when the estimated set fits in `work_mem × hash_mem_multiplier` (8 MB with defaults). A wide `or` rule with no candidate filter (dry-run, saved search, AI search) can exceed that. Examples are many large products in one `in`, or several product conditions, and `UNION ALL` keeps one row per matching CPE-match row rather than per CVE. The planner then falls back to a plain SubPlan, rescanned per `cves` row across 2.6 million rows, which would exceed the 14 s timeout. The measured `or` rows are single products. §13's 50-value measurement does not say `or` or broad products, and the `work_mem` of the kept ingest is not stated. The project sets no `work_mem` (a repository-wide grep finds none).
- **Probe:** with `SET work_mem = '4MB'`, run `EXPLAIN` of an `or` rule with `affected.cpe_product in [<20+ broad products, for example the Windows 10 and Server releases>] OR in_cisa_kev` and no candidates, and check for "hashed SubPlan" against "SubPlan".
- **Axes:** contestable until probed. Remedy is a choice: add the `or` case to §13 with stated `work_mem`, use `UNION` (dedupe) rather than `UNION ALL`, or compile `or` product conditions to `EXISTS`.

### R9 · downstream readiness (PLAN §10.2 and pitfall ARCH-2), seams & contracts
- **Anchor:** §4.1: "Stored ecosystems are canonical OSV names (`internal/ecosystem`), so ecosystems are compared exactly, where today's compiler lower-cases them."
- **Claim:** PLAN §10.2 makes case-insensitive comparison a requirement: "All DSL text operator evaluations (`contains`, `starts_with`, `ends_with`, `eq`, `neq`) MUST normalize both the rule literal and the CVE field value to lowercase". The design drops that for `affected.ecosystem` `eq`/`in`, but §11's list of PLAN.md changes does not record the departure. It also makes rule matching differ from the package watchlist match, which still uses `lower(cap.ecosystem) = lower(wi.ecosystem)` (`compiler.go` `watchlistExpr`). The practical effect is small: `ecosystem.Valid` already refuses non-canonical case in rule values, and OSV stores canonical names.
- **Axes:** objective (the PLAN conflict is not listed). Remedy is a choice: add a §10.2 note to §11, or keep the comparison case-insensitive in a form the index can use.

### R10 · downstream readiness, seams & contracts
- **Anchor:** §3.2, §8, §10 ("`FieldDescription.TypeDesc` for the field is `"CPE vendor:product"`").
- **Claim:** A plan author would have to decide the following, which the design leaves open:
  - **Field registry shape.** `ExportFieldDescriptions` derives `TypeDesc` from `fieldKind`. `kindAffected` yields "affected product" and routes through `affectedSQL`'s `switch c.Field`. Giving the field its own `TypeDesc` needs a new kind or a special case, and the design names neither.
  - **Compile-time enforcement.** Limits are checked in `Validate`, which runs only at save. The design does not say whether `Compile` re-applies the value parser and the 50/100 limits to stored rules, or what it does on failure. A `Compile` error makes the evaluator set the rule's status to `error` (`failUncompilableRule`), so this decides the behaviour of stored rules after a later change to the parser or the name table.
  - **Duplicates.** The design does not say whether duplicate values within or across product conditions count towards the 50, or are deduplicated before SQL is built.
  - **Create/PATCH symmetry.** §12 tests the limits only at unit level (`Validate`), not through both create and PATCH (testing-pitfalls §4, Validation Symmetry).
- **Axes:** objective (the gaps exist). Each remedy is a small choice.

### R11 · unstated assumptions, downstream readiness
- **Anchor:** §2: "The project supports PostgreSQL 15 and later; plans were measured on 18 only." §13: "if CI or a deployment runs a PostgreSQL major other than 18, the realtime and dry-run rows again on that major".
- **Claim:** The trigger for re-measuring on another major never fires in the project's own infrastructure. `internal/testutil/postgres.go`, `docker/compose.yml` and `docker/compose_test.go` all use `postgres:18-alpine`. So supported majors 15–17 are never measured. PostgreSQL 18 added planner features that bear on the shapes measured: btree skip scan, which matters for R4 and the no-ecosystem package row, and conversion of OR lists to arrays in index scans, which matters for the bitmap `OR` of ranges and names. Plans measured on 18 may not carry over.
- **Axes:** contestable. Remedy is a choice: measure the realtime and dry-run rows on 15 once, or state that performance is verified on 18 only.

### R0 · requirements trace (standing)
- Requirements completeness unverifiable: the requirement is unpinned. §1 says it paraphrases MATCH-2 and that Sam has not confirmed the wording. Internal consistency was checked instead. The design flags each place where it departs from its own §1: the Brotli acceptance case (open question 1), watchlists (open question 3), and correlation scope (open question 6). The one unflagged inconsistency is R1.

## Per-lens results

- **Requirements trace:** R0 (standing: unpinned), R1.
- **Simplicity & proportionality:** R3. Its 100-condition limit does not close the failure that is its stated justification, so it costs code and removes no failure. No other significant findings. The shared name table, set form and parity test are each justified by a stated requirement or measurement.
- **Seams & contracts:** R2 (the validator promises warnings; the API side drops them), R5 (the check and the rule read the same CNA rows with different meanings), R9 (rule and watchlist ecosystem comparison diverge), R10 (the Validate/Compile contract for limits).
- **Failure modes:** R2, R3, R4, R8.
- **Unstated assumptions:** R4, R5, R8, R11.
- **Alternatives & rationale:** R5, R6, R7.
- **Change & reversibility:** R2 (stored rules of the multi-ecosystem shape go dead with no signal), R7 (the hash change may need repeating for MATCH-3). Back-out paths for correlation (§4.3) and the hash change (§7) are stated.
- **Downstream readiness:** R1, R3, R4, R6, R9, R10, R11. Pitfalls docs were read (`dev/implementation-pitfalls.md`, `dev/testing-pitfalls.md`). The design walks into DB-12 (R3), NOTIFY-2 (R6) and the PLAN §10.2 / ARCH-2 case-insensitivity rule (R9), and its test plan does not cover testing-pitfalls §4, Validation Symmetry (R10).

## Claims checked and confirmed

These settle claims the findings above do not depend on, so a reader can skip them:
- `go list -deps ./internal/check`: it imports only `internal/ecosystem` and `internal/version` within the module, so `internal/alert/dsl` importing it creates no cycle. `internal/store` imports `internal/alert/dsl` (`dsl_executor.go`).
- Only the NVD adapter writes `CPEMatches`. MITRE CNA CPEs go to `AffectedCPEs` only, and both MITRE and NVD's relay write `CNAAffected`.
- `cpe_normalized` is lower-cased at ingest (`internal/feed/nvd/adapter.go`).
- Realtime runs only on a hash change, including for a new CVE: `GetCVEMaterialHash` returns `""` for a missing row.
- `resolveCNAAffected` keeps every distinct copy, so one CNA edit can move the proposed hash twice, as §7 says.
- The Node table row gives 6 ranges and 3 names today, and 5 names with the two additions, so §3.2's 38 parameters is correct.
- The golden NVD page holds CVE-2026-56847 (CNA `nodejs`/`node`, NVD `nodejs:node.js` vulnerable) and CVE-2026-111497 (NVD lists `google:brotli` and `nodejs:node.js` vulnerable), as §12 states.
