# Independent review, round 4: product conditions and correlated package conditions in alert rules (MATCH-2)

Reviewed: the snapshot at `the design at commit 2713b8b (a scratch copy)` (cold read; no prior review artifacts or history read). Claims were checked against the work tree at `the worktree`. No database was queried.

Findings are ranked from most to least severe across all lenses. The per-lens lines are at the end.

---

## R1. The 50-value cap leaves out `affected.ecosystem` values, and those values now expand into bind parameters

- **Lenses:** failure modes; downstream readiness (pitfall DB-12); seams & contracts
- **Doc anchor:** §3.2 Operators, "A rule holds at most 50 values across all its `affected.cpe_product` and `affected.package` conditions together". Also §5.1, `(cap.ecosystem = $eco1 OR starts_with(cap.ecosystem, $eco1 || ':') OR ...)   -- each ecosystem condition`, and the predicate table, "For each pair of ecosystem value and name ... `(cap.ecosystem = $e AND <folded name> = $n)`, `OR`-ed".
- **Claim:** The cap is meant to keep a rule under PostgreSQL's 65,535-parameter limit and to bound the size of the realtime plan. It does not do either, because the new SQL also emits terms for each `affected.ecosystem` value, and nothing caps those.
  - The ecosystem filter emits one or two parameters per ecosystem value.
  - The `eq`/`in` package predicate emits one `(ecosystem, name)` term per pair, so the term count is the number of ecosystem values times the number of package names.
- **Evidence:**
  - Today `affectedEcosystemSQL` (`internal/alert/dsl/compiler.go:301-330`) binds every ecosystem value as one array parameter (`lower(cap.ecosystem) LIKE ANY(?)` with `pq.Array(patterns)`). That form follows DB-12 and has no parameter limit.
  - `Validate` (`internal/alert/dsl/validator.go:198-221`) puts no length limit on an `in` list. `ecosystem.Valid` accepts any suffix on a base that takes one, so `Debian:1`, `Debian:2` and so on are all valid values.
  - The global 1 MiB request limit allows tens of thousands of such values. At one or two parameters each, the ecosystem filter alone can pass 65,535.
  - Within the limit, the pairs still multiply. For example, `ecosystem in [45 bases]` with `package in [50 names]` gives 2,250 pair terms. That is the planning cost the cap was meant to bound, paid on every realtime evaluation.
  - §3.2 names the outcome itself: "fail on every evaluation, which holds the batch cursor for all rules" (`batchMaxHeldRuns` = 30, `internal/alert/evaluator.go:173-176`).
  - `dev/implementation-pitfalls.md` DB-12: "Never use dynamic `IN ($1, $2, ..., $N)` construction for user-controlled lists."
- **Axes:** Objective. The remedy is a choice:
  - count ecosystem values, or ecosystem-value-by-name pairs, in the cap;
  - keep the ecosystem filter as one array parameter;
  - add a compile-time parameter guard, so `failUncompilableRule` sets the rule to `error` instead of letting it fail on every run.

## R2. Requirement 5 is restated without the requirement's own example, so §1 already assumes the answer to open question 1

- **Lenses:** requirements trace (internal consistency)
- **Doc anchor:** §1, item 5: "A rule `{affected.cpe_product eq nodejs:node.js, severity in [critical, high]}` matches a Node CVE on the day the CNA record lands". Compare §2: "The requirement's own example, the Brotli CVE CVE-2026-111497, cannot match", and §15 Q1: "The requirement's example, the Brotli CVE, names only `Google` / `Brotli`".
- **Claim:** §2 and §15 say the requirement's acceptance case names the Brotli CVE. §1's paraphrase drops that CVE and reads as "a Node CVE", which is Q1's proposed substitute. The requirements section therefore already holds the proposed narrowing. A reader who checks the design against §1 alone sees no gap, and §1 is the only requirement text in the document while it is unpinned.
- **Evidence:** §1 never mentions CVE-2026-111497. §2 row 1 and §15 Q1 both say the requirement names it.
- **Axes:** Objective, because the document contradicts itself. The remedy is determinate: state the requirement's example in §1 as given, and leave the substitution to Q1.

## R3. §7's recommended hash change costs more than the one-time re-hash: unmeasured re-fires continue afterwards, including from MITRE/NVD copy divergence

- **Lenses:** alternatives & rationale; unstated assumptions; failure modes
- **Doc anchor:** §7, "Cost: the hash of every CVE with CNA rows (405,809 of about 2.6 million) changes on its next merge ... spread over the weeks", and "Lower-casing keeps the NVD relay and the MITRE copy of one entry from moving the hash when they differ only in case."
- **Claim:** The cost paragraph covers only the one-time move of existing hashes. After that, every CNA product edit moves the hash, and every rule that matches the CVE re-fires, including rules with no product condition such as `severity eq critical`. Stored CNA rows are the union of the MITRE copy and NVD's relay, and the merge keeps both even when they differ. So one CNA edit can move the hash twice: once when MITRE delivers it, so the set holds the old and new pairs, and again when NVD's relay catches up and the old pair drops out. Each move is a new `alert_events` row and a new notification. The design measures neither the rate of these edits nor how often the two copies differ in the pairs it hashes. That rate is what the choice between the hash change and the separate evaluation signal turns on.
- **Evidence:**
  - `internal/merge/resolve.go:307-311`: "the MITRE copy and NVD's relay can differ. CNA data can only report a version as affected or unresolved, so keeping a stale copy is the safe direction". Entries are deduplicated by their whole JSON form across sources.
  - `alert_events` is unique on `(org_id, rule_id, cve_id, material_hash)` (PLAN.md §10.4), so each new hash fires again.
  - Probe for the runner (read-only, on the kept ingest):

    ```sql
    WITH pairs AS (
      SELECT s.cve_id, s.source_name,
             lower(coalesce(e->>'vendor','')) || E'\x1f' || lower(coalesce(e->>'product','')) AS vp
      FROM cve_sources s, jsonb_array_elements(s.normalized_json->'cna_affected') e
      WHERE s.source_name IN ('mitre','nvd')
    ), sets AS (
      SELECT cve_id, source_name, array_agg(DISTINCT vp ORDER BY vp) AS ps FROM pairs GROUP BY 1, 2
    )
    SELECT count(*) AS both_sources,
           count(*) FILTER (WHERE m.ps IS DISTINCT FROM n.ps) AS pair_sets_differ
    FROM sets m JOIN sets n USING (cve_id)
    WHERE m.source_name = 'mitre' AND n.source_name = 'nvd';
    ```
- **Axes:** Contestable: how much re-fire noise is acceptable is Sam's call. The remedy is a choice: measure the rate, hash only one copy, or prefer the separate evaluation signal.

## R4. The rationale for not reading `cve_affected_cpes` describes that table as NVD-only, but it also holds the CNA's own CPEs, which are day-one data

- **Lenses:** alternatives & rationale; unstated assumptions
- **Doc anchor:** §3.3, "`cve_affected_cpes`. It holds NVD's platform CPEs (`vulnerable = false`) beside the vulnerable ones, which roughly doubles the matches for operating systems (section 2), and it gave no day-one gain in the sample."
- **Claim:** `cve_affected_cpes` is not only NVD's criteria. It also holds:
  - the CPE strings a CNA puts in its own record (`containers.cna.affected[].cpes`), which arrive with the CNA record, before NVD analysis — exactly the window requirement 5 is about;
  - MSRC product names;
  - Red Hat CPEs.

  The design weighs the table only as "NVD platform CPEs". The evidence that it adds no day-one data is a 12-product sample with one unanalysed CVE among the extras. A middle option is not weighed: read the CNA-supplied CPEs and leave out the NVD platform CPEs. The table has no source column, so that option needs either a source column or a read of `cve_sources`.
- **Evidence:**
  - `internal/feed/mitre/adapter.go:398-417` appends `affected[].cpes` to `patch.AffectedCPEs`.
  - `internal/feed/msrc/adapter.go:177-193` and `internal/feed/redhat/adapter.go:240-256` write `AffectedCPEs` too.
  - `migrations/000002_create_cve_core.up.sql` gives `cve_affected_cpes` only `cve_id`, `cpe` and `cpe_normalized`.
  - Probe: count the CVEs with a CNA `cpes` entry for each sampled product and no vulnerable `cve_cpe_matches` row, from `cve_sources.normalized_json` where `source_name = 'mitre'`.
- **Axes:** Contestable: the sample may be representative. The remedy is a choice: record the omission and its reason, or measure it.

## R5. Nothing in the design shows why a new `internal/product` package is needed: `internal/alert/dsl` can import `internal/check` directly

- **Lenses:** simplicity & proportionality; alternatives & rationale
- **Doc anchor:** §3.1, "moved with the name table to a package both can import (section 3.4)"; §3.4, "A new package `internal/product` takes everything both callers need ... The compiler cannot import `internal/store`, which imports `internal/alert/dsl`".
- **Claim:** The stated reason, a package both callers can import, does not separate the new package from `internal/check`, which both callers can already import. Only the two store helpers, `cpeIndexExpr` and `cnaNameIndexExpr`, are out of the compiler's reach. They could move into `internal/check`, which `internal/store` already imports, and whose `CPEKeyRunes` they already use. The new package moves about 15 identifiers, plus their tests (`names_test.go`, `keys_test.go`, part of `input_test.go`) and the index pin tests. That cost is real and current, and the doc records no alternative. A cohesion argument may exist, such as a smaller dependency surface for the compiler (`internal/check` brings in `internal/version` and `packageurl-go`), but the doc does not make it.
- **Evidence:**
  - `go list -deps ./internal/check` lists only `internal/ecosystem` and `internal/version` among project packages, so `dsl -> check` makes no import cycle.
  - `internal/store/check.go:43-44` builds `cpeIndexExpr` from `check.CPEKeyRunes`.
- **Axes:** Contestable. The remedy is a choice: record the reason, or import `internal/check` directly.

## R6. The word-boundary test and the hash's case folding depend on the database locale and the PostgreSQL version; the parity test covers one configuration

- **Lenses:** unstated assumptions; failure modes
- **Doc anchor:** §5.1, "In SQL the following character is tested with `!~ '^[[:alnum:]]'`. Go's `unicode.IsLetter` and PostgreSQL's `[[:alnum:]]` can disagree outside ASCII, so a parity test runs every other-product entry ... through both". Also §7, "lower-cased as the match compares them".
- **Claim:** In PostgreSQL, what `[[:alnum:]]` and `lower()` do with a non-ASCII character depends on the database's ctype and collation provider: in the C locale, non-ASCII characters are not alphanumeric, and in a Turkish locale `lower('I')` is a dotless i. The parity test runs against the `postgres:18-alpine` test container's locale only (`internal/testutil/postgres.go:198`). The project supports PostgreSQL 15 and later under any locale, so a passing parity test does not show parity on a deployment. Two smaller points:
  - The hash in §7 lower-cases CNA names in Go (`strings.ToLower`), while the match lower-cases in SQL. CNA names are stored as sent, so they can be non-ASCII; the rule's ASCII restriction applies only to rule values.
  - §2 says plans were measured on PostgreSQL 18 only, and §13 repeats the measurements on the same instance. Nothing says whether PostgreSQL 15 to 17 must be checked.
- **Evidence:** The PostgreSQL documentation on regex character classes and on `lower()` says both depend on the locale's `LC_CTYPE`. Probe: run `SELECT 'é' ~ '^[[:alnum:]]', lower('I')` in databases created with `--locale=C`, `en_US.UTF-8` and `tr_TR.UTF-8`.
- **Axes:** Mostly objective; the impact is small, since it needs a product name followed by a non-ASCII letter. The remedy is a choice: an explicit ASCII class (`[A-Za-z0-9]`) in both Go and SQL removes the dependence, or the doc states the assumption.

## R7. A product that ends in a lone backslash is accepted, so "every product a rule accepts, the check accepts too" is false

- **Lenses:** failure modes (hostile input); seams & contracts
- **Doc anchor:** §3.1, "The rule adds one refusal the check does not make ... So every product a rule accepts, the check accepts too."
- **Claim:** In a rule value the product is the last component, so it can end in a lone backslash. Each check passes it:
  - `splitCPE("nodejs:node.js\\")` returns two parts.
  - `dropRedundantEscapes` keeps the trailing backslash.
  - `escapedAsCPERequires` skips past the end and returns true.
  - `literalCPEValue` is true.

  The prefix the compiler builds is then `cpe:2.3:a:nodejs:node.js\:`, where the backslash escapes the separator, so it matches products that start with `node.js\:`. In the check endpoint, the same backslash escapes the next colon of the 13-component string, so the check refuses the CPE as `invalid_cpe`. The claim in the anchor is therefore false.
- **Evidence:** `internal/check/input.go:255-267` (`escapedAsCPERequires`, where `case c == '\\': i++` runs past the end), `273-285` (`dropRedundantEscapes`) and `298-311` (`splitCPE`).
- **Axes:** Objective. The remedy is determinate: refuse a trailing unescaped backslash, add an error row in §8 and a test in §12.

## R8. The compile rules for several ecosystem conditions with a package condition are ambiguous, and one existing rule shape silently becomes unsatisfiable

- **Lenses:** downstream readiness; requirements trace; failure modes
- **Doc anchor:** §4.2, "each `affected.package` condition must hold on one `cve_affected_packages` row together with every `affected.ecosystem` condition that uses `eq` or `in`"; §5.1, "-- each ecosystem condition" and "For each pair of ecosystem value and name"; §4.2, "A rule with ecosystem conditions and no package condition matches as today".
- **Claim:** A plan author would have to decide three things the doc does not settle:
  - **How two `eq`/`in` ecosystem conditions combine with a package condition.** "Every" implies AND across the conditions. Then today's valid `and` rule `{ecosystem eq npm, ecosystem eq PyPI, package contains x}` (a CVE with an npm row and a PyPI row, and some package `x`) matches nothing. §4.3 says such rules match "fewer CVEs", not none, and §8 has no warning for contradictory ecosystem conditions. "Each pair of ecosystem value and name" is undefined when the values come from more than one condition.
  - **Whether a rule with only ecosystem conditions compiles to the set form or keeps today's `EXISTS`.** §5.1 says ecosystem `eq`/`in` compile differently now; §4.2 says they match "as today".
  - **Whether an ecosystem condition that a package condition absorbs is also emitted on its own.**
- **Evidence:** The quoted passages. `internal/alert/dsl/compiler.go:301-330` is today's ecosystem form.
- **Axes:** The ambiguity is objective. The remedy is determinate once Sam picks the semantics, for example AND plus a validator warning for disjoint values.

## R9. The "same answer on every path" test needs IDs that DryRun does not return

- **Lenses:** downstream readiness
- **Doc anchor:** §12, "the CVE IDs from dry-run (no candidate IDs) equal the IDs from evaluating the corpus in 1,000-ID pages, as activation does."
- **Claim:** `Evaluator.DryRun` returns `MatchCount` and at most 10 `SampleCVEs` (`internal/alert/evaluator.go:444-457`). It does not return the matched IDs, so the test cannot compare ID sets through it. A plan author must choose a hook: call `queryCandidates` from an in-package test, use `ExecuteDSLQuery` pages, or compare counts only.
- **Evidence:** The `DryRunResult` fields at `internal/alert/evaluator.go:76-82` and `452-457`.
- **Axes:** Objective. The remedy is a choice.

## R10. `CompiledRule.Where` does not define what an empty candidate slice means

- **Lenses:** seams & contracts
- **Doc anchor:** §5.2, "`CompiledRule.Where(candidateIDs []string) sq.Sqlizer` ... `DryRun`, `store.ExecuteDSLQuery` | none".
- **Claim:** `queryCandidates` treats any `len(candidateIDs) == 0` as no filter (`internal/alert/evaluator.go:607`). If `Where` tests for `nil` instead, a non-nil empty slice produces inner sets of `= ANY('{}')`, which match nothing, while the outer query scans the whole corpus. The two forms then disagree. The contract should say that nil and empty both mean no candidates.
- **Evidence:** `internal/alert/evaluator.go:600-609`.
- **Axes:** Objective; low impact, since no current caller passes an empty slice. The remedy is determinate.

## R11. The measurement queries cannot be found from the repository, but §13 requires repeating them

- **Lenses:** downstream readiness; change & reversibility
- **Doc anchor:** §5.3, "The measurement queries are read-only SQL kept in the shared session notes outside the repository, beside their outputs"; §13, "the section 5.3 rows for realtime ... batch (5,000 IDs) ...".
- **Claim:** §13 sets merge gates on these measurements ("A realtime row over 5 ms ... goes back to Sam"). The exact queries and inputs are in no location a later reader can find: which CVE was the realtime candidate, how the 5,000 batch IDs were chosen, and the cache state. Re-measured numbers therefore cannot be compared with the baseline like for like. The reference also fails the self-identifying-reference rule: "shared session notes" gives no path.
- **Evidence:** The quoted text; the doc gives no path.
- **Axes:** Objective. The remedy is determinate: commit the queries, or give their path.

## R12. An exact package match with no ecosystem is left slow, and the alternatives are not weighed

- **Lenses:** alternatives & rationale; failure modes
- **Doc anchor:** §5.3, "Dry-run, `affected.package eq openssl`, no ecosystem | not applicable | 10.5 s", and "AI search acts only on validation errors ... so a generated rule of that shape runs with no warning shown, within 4 s of the 14 s timeout"; §6, "None are added."
- **Claim:** The doc expects the AI search to generate this shape ("lodash vulnerabilities") and expects it to come within 4 s of the statement timeout on today's corpus, which grows. The doc records no alternatives. Two obvious ones:
  - an index on the folded name alone. Migration 000061 dropped the old package index because "No query can use this index", so its write cost is known;
  - compiling the no-ecosystem `eq` as a list of the ecosystems actually present, so `cve_affected_packages_check_idx` applies.
- **Evidence:** §5.3, §6, and `migrations/000061_bounded_cpe_and_package_keys.up.sql:20-24`.
- **Axes:** Contestable. The remedy is a choice: record the rejected options, or accept the risk explicitly.

## R13. §7's cost statement leaves out the effect on `date_modified_canonical` and on batch load; reverting the correlation change has no stated path

- **Lenses:** change & reversibility
- **Doc anchor:** §7, "The golden material hashes are regenerated in the same pull request ... Reverting the change later moves the same hashes back, at the same cost."; §4.3, "This design does not [bump `dsl_version`]".
- **Claim:**
  - **`date_modified_canonical`.** A hash change bumps `date_modified_canonical` (`internal/merge/pipeline.go:178-179`), so 405,809 CVEs show as modified to API clients polling by modified date. The batch evaluator also re-scans them for every rule. The doc's alternative paragraph shows the author knows `date_modified_canonical` must keep meaning "materially changed", but the recommendation's cost does not mention the bump.
  - **Reverting the correlation change.** Rules keep `dsl_version` 1 across the change, so nothing records which reading a rule was saved under. Reverting widens the rules again: events resolved under the narrow reading reopen when their CVEs are next evaluated, and resolution notifications already sent cannot be withdrawn. The doc does not state this.
- **Evidence:** As quoted; `internal/merge/pipeline.go:178-199`.
- **Axes:** Objective that the doc does not state these. Their weight is contestable, given no users.

## R14. A whitespace-only package value is not refused

- **Lenses:** downstream readiness (testing-pitfalls §4)
- **Doc anchor:** §4.1, "An empty value is refused."; §8, "`affected.package` `eq` or `in` with an empty value | error".
- **Claim:** `dev/testing-pitfalls.md` §4 says whitespace-only strings count as empty. `"   "` folds to itself and matches nothing, so a rule with it saves without error and never fires.
- **Evidence:** `ecosystem.FoldPackageName` does not trim (`internal/ecosystem/ecosystem.go:109-115`).
- **Axes:** Objective; low impact. The remedy is determinate.

---

## Per-lens results

- **Requirements trace:** R2, R8. Standing finding: requirements completeness unverifiable — unpinned. Apart from R2, every design element traces to §1 or to a stated future direction: §9 for watchlists, §14 for version conditions and `package_key`.
- **Simplicity & proportionality:** R5.
- **Seams & contracts:** R1, R7, R10.
- **Failure modes:** R1, R3, R6, R7, R8, R12. Security: no further findings. Rule values are passed as parameters, product matching reads only the global corpus tables, and AI-generated rules go through `Validate`.
- **Unstated assumptions:** R3, R4, R6.
- **Alternatives & rationale:** R3, R4, R5, R12.
- **Change & reversibility:** R11, R13.
- **Downstream readiness:** R1, R8, R9, R11, R14. Pitfalls check:
  - DB-12 (dynamic `IN` lists against the 65,535-parameter limit): violated for ecosystem values, see R1.
  - ARCH-2 and ARCH-46 (case-insensitive comparison): met.
  - DB-22 and ARCH-47 (sort before hashing): met; §7 sorts by vendor, then product.
  - NOTIFY-10 (rejected and withdrawn filter): met by `queryCandidates`.
  - DB-26 (btree over unbounded text): not applicable; no new indexes.
  - testing-pitfalls §2 (SQL and Go case agreement): partly covered by the parity test, see R6.
  - testing-pitfalls §4 (whitespace-only input): see R14.
