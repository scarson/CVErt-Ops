7369080

# Cold-read review: product conditions and correlated package conditions in alert rules (MATCH-2)

Reviewer: Fable, all eight lenses. Source read at the work tree for claims about code. No database query was run. The document's 11 "Verify before building" notes are treated as known; they are not re-reported one by one, except where a lens finding is about their combined effect (R3) or where one walks into a pitfalls entry.

Commands run for evidence: `go list -deps ./internal/check`; `go list -f '{{.Imports}}'` on `internal/testutil`, `internal/alert/dsl`, `internal/ai`; greps and reads of `internal/alert/dsl/{compiler,validator,field}.go`, `internal/alert/{evaluator,cache}.go`, `internal/check/{names,keys}.go`, `internal/store/{check,dsl_executor}.go`, `internal/ecosystem/ecosystem.go`, `internal/merge/hash.go`, `migrations/000059`, `000061`, PLAN.md sections 10.2 and 10.5, and both pitfalls documents.

## Findings, most severe first

### R1. A product `in` list has no stated set structure, and the natural one applies the other-product exclusion to the wrong values

- **Lenses:** seams & contracts; failure modes; downstream readiness.
- **Anchor:** section 5.1, "`AND NOT (...)                            -- the product's other products`"; section 3.2, "Each product value becomes its own `OR` terms and bind parameters".
- **Claim:** The document gives the SQL "For a product" (one value) only. For `affected.cpe_product in [a, b, ...]` it does not say whether each value gets its own set, or all values share one set with their terms `OR`-ed. In the shared-set reading, which section 3.2's wording suggests, the single branch-level `AND NOT (...)` excludes a row that is an other product of value `a` even when the row is a name row of value `b`.
- **Evidence:** `otherProducts` is keyed by one CPE (`internal/check/names.go:95-105`): `microsoft:.net` excludes vendor `microsoft` with product prefix `.net framework`. `ownNames` for the real CPE `microsoft:.net_framework` yields `microsoft` / `.net framework` (`names.go:185-195`). So `in [microsoft:.net, microsoft:.net_framework]` compiled as one set with one `NOT` drops the CNA row `Microsoft` / `.NET Framework` that the second value names; compiled as `(names_a AND NOT others_a) OR (names_b AND NOT others_b)` it keeps it. The version check does not have this problem because `itemKeys.otherProducts` is per item (`internal/check/keys.go:118-120,150`). Section 12 has no test with two values in one condition where one value's other product is the other value's name.
- **Axes:** objective (the structure is unstated and one reading is wrong); remedy determinate (scope the exclusion per product value, state it, add the test).

### R2. The reason for rejecting both remedies to the 10.5 s package shape is contradicted by the document itself, and the simplest remedy is not weighed

- **Lenses:** alternatives & rationale; failure modes (resource exhaustion); unstated assumptions.
- **Anchor:** section 5.3, "a shape the warning already discourages"; section 8, "this match cannot use an index, so dry-run and saved searches can be slow".
- **Claim:** `affected.package eq X` with no correlated ecosystem runs 10.5 s against a 14 s timeout. The index on the folded name is rejected because "the warning already discourages" the shape. The same paragraph says AI search "acts only on validation errors ... so a generated rule of that shape runs with no warning shown", and the section 8 note says create, PATCH and saved searches drop warnings too. The warning reaches a caller only through `POST .../validate`, so it does not discourage the shape on any path that executes it. The rationale does not distinguish the chosen option from the rejected ones.
- **Evidence:** quotes above. The 10.5 s figure is warm cache, PostgreSQL 18, one host (section 5.3 heading); the margin to the timeout is 3.5 s, and nothing states what a cold cache or a smaller host does to it. `ExecuteDSLQuery` runs the statement on a pooled connection for any org member (`internal/store/dsl_executor.go:121-183`), so each such saved search holds a connection for the duration. Unweighed alternative: make `affected.package` `eq`/`in` without an `eq`/`in` ecosystem condition in an `and` rule a validation error (the operator is new, so no stored rule breaks), which removes the slow shape with no index and no extra query. Substring operators already cover "any ecosystem".
- **Axes:** the contradiction is objective; the remedy is a choice (error, index, or accept with a real statement of the risk).

### R3. Eleven "Verify before building" notes hold undecided design decisions that section 15 does not list

- **Lenses:** downstream readiness; requirements trace (internal consistency).
- **Anchor:** header, "11 verify-first flags annotated in place"; section 15, "Open questions for Sam".
- **Claim:** A plan author cannot write the plan without making these decisions, and section 15 (the stated place for Sam's decisions) names none of them. At least seven are decisions, not checks:
  1. whether CNA entries whose versions are all `unaffected` match (section 3.3);
  2. whether create and PATCH return warnings or the several-ecosystems shape becomes an error (section 8);
  3. exact or `lower()` ecosystem comparison, and the PLAN.md §10.2 change that goes with it (section 4.1);
  4. whether the vulnerable flag joins the hash change or the separate signal (section 3.5);
  5. the field kind, whether `Compile` re-applies parsing and limits to stored rules, how duplicates count toward 50 (section 5.2);
  6. list binding: `= ANY(?)` everywhere or a list-length cap, and the recount (section 3.2);
  7. which seeded record the acceptance-form test uses (section 12).
- **Evidence:** Each note's own text says "Decide", "Re-decide", "Either ... or", or "a plan author still has to decide". Section 3.2's body still states the claim its note calls false ("as the compiler binds `in` lists today"; `setSQL` uses `sq.Eq{sqlExpr: vals}`, `internal/alert/dsl/compiler.go:246-249`), and the worst-case parameter count "under 3,000" rests on it.
- **Axes:** objective; remedy determinate in form (decide each, or move each to section 15), a choice in content.

### R4. The parity test asserts an agreement that section 5.1 says the database does not guarantee

- **Lenses:** failure modes; unstated assumptions; downstream readiness. Pitfall: testing-pitfalls §2, case-sensitivity divergence between SQL and application layers (same class: one condition evaluated by two engines).
- **Anchor:** section 12, "a non-ASCII letter (`é`), the SQL exclusion and `isOtherProduct` agree"; section 5.1, "matches or is excluded in one locale and not another".
- **Claim:** Section 5.1 accepts that `[[:alnum:]]` follows the database's character type and can disagree with Go's `unicode.IsLetter`. Section 12 then asserts agreement for `é`. Whether that test passes depends on the test container's ctype, which the document does not state, and a pass there says nothing about a deployment with a C ctype. In such a deployment a rule excludes a CNA row that the version check keeps, against section 3.4's "a rule and a check of one product read the same CNA rows".
- **Evidence:** `isOtherProduct` uses `unicode.IsLetter`/`unicode.IsDigit` (`internal/check/names.go:111-119`). Test databases are `postgres:18-alpine` (`internal/testutil/postgres.go:198`). Probe the runner must execute (I was told not to query containers): in a test database and in a database created with `LOCALE 'C'`, `SELECT 'é' ~ '^[[:alnum:]]', datcollate, datctype, datlocprovider FROM pg_database WHERE datname = current_database();`. Unweighed alternative that removes the dependence: test the following character against an ASCII class on both sides (table names are ASCII), or pin the regex's collation and make the Go rule match it.
- **Axes:** the contradiction between the two sections is objective; the remedy is a choice.

### R5. The worst-case statement for the candidate paths is neither described nor in the measurement plan

- **Lenses:** unstated assumptions; failure modes (resource exhaustion); downstream readiness.
- **Anchor:** section 5.2, "the set repeats the same list"; section 13, "a rule of 50 product values ... and 100 conditions, realtime against one CVE and dry-run"; section 13, "A realtime row over 5 ms, a dry-run over 5 s ... or an activation over 7 minutes goes back to Sam".
- **Claim:** Every set branch carries its own copy of the candidate array (two per product set, one per package set, one more in `queryCandidates`). Squirrel numbers each `?` separately, so the copies cannot share a parameter. A batch chunk is 5,000 IDs (`candidateCap`, `internal/alert/evaluator.go:29,584`). A rule at the limits therefore sends on the order of 100 to 200 copies of a 5,000-element array per chunk. Section 13 measures the limit rule on realtime (one ID) and dry-run (no IDs), which are the two paths where this cost is absent, and the "back to Sam" thresholds have no batch row. A rule that errors or times out in batch holds the cursor for every rule for up to 30 runs (`batchMaxHeldRuns`, `evaluator.go:166-176`), the outcome section 3.2 cites DB-12 to avoid.
- **Evidence:** as cited. Also unstated: which 50 products the activation measurement uses (50 large products and 50 unmapped ones differ by orders of magnitude in matches), and the per-match cost inside a page: `evaluateRule` runs `cveExists` and `InsertAlertEvent` as separate statements per matched CVE (`evaluator.go:505-524`), which the "under about 340 ms a page" budget does not mention.
- **Axes:** objective (unmeasured and unstated); remedy determinate for the measurement (add batch at 5,000 IDs with the limit rule, name the products, add a batch threshold); a choice for the shape (for example one candidate CTE referenced by every branch).

### R6. Back-out is stated for correlation and the hash, and not for stored rules that use the new field or operators

- **Lens:** change & reversibility.
- **Anchor:** section 4.3, "reverting the correlation is a code revert"; section 3.2, "Either can be added later without changing stored rules."
- **Claim:** After this ships, rules and saved searches can hold `affected.cpe_product` and `affected.package` `eq`/`in`. If the code is reverted, `Compile` returns `unknown field` or `unsupported package op` (`internal/alert/dsl/compiler.go:29-32,346-347`), and every such rule is set to `status=error` on its next evaluation (`failUncompilableRule`, `internal/alert/evaluator.go:654-659`); re-enabling runs a new activation scan. The document does not state this path or its cost, and does not say what a stored saved search with the field does after a revert.
- **Evidence:** as cited; section 4.3 and section 7 each state their own revert path, so the omission is specific to the field and operators.
- **Axes:** objective; remedy determinate (state it).

### R7. A name-table edit changes what stored rules match and nothing evaluates the change

- **Lenses:** failure modes; unstated assumptions. Pitfall: NOTIFY-2 ("Document the limitation is not an acceptable resolution for a correctness failure in a security alerting system").
- **Anchor:** section 3.4, "nothing re-evaluates the corpus for it."
- **Claim:** Adding a CNA spelling or an other-product entry in a release changes rule matches for CVEs already stored. A CVE that newly matches gets no event until its next material change; one that stops matching keeps an open event until then. The document records this as a fact and gives no operator step (for example re-running activation for product rules after a table change), no test, and no entry in section 15. Section 7's open question 2 also still offers "or neither (a documented gap)", the resolution NOTIFY-2 rejects, without citing the pitfall there (the section 3.5 note cites it for the vulnerable flag only).
- **Evidence:** quotes above; `EvaluateActivation` is the only full-corpus path and runs only for a rule in `activating` (`evaluator.go:301-360`).
- **Axes:** contestable (the project has no users, and the two rows added now change no match); remedy a choice.

### R8. Requirements completeness unverifiable — unpinned (standing), and two internal inconsistencies

- **Lens:** requirements trace.
- **Anchor:** section 1, "Status: unconfirmed."
- **Claim and evidence:**
  - Standing: requirements completeness unverifiable — unpinned. Section 15 question 7 marks this open.
  - Requirement 5 as written cannot be met by the design (section 2, first row). This is marked open (question 1), so it is consistent, but the document has no acceptance criterion in force until Sam answers.
  - Requirement 3 says "exact-match operator". Section 4.1 delivers equality after folding ("`Foo_Bar` matches PyPI `foo-bar`"), which is case-insensitive everywhere and separator-insensitive on PyPI. No operator compares the stored spelling exactly. The folding is defensible (ARCH-2), but the restatement is not called out as a reading of the requirement and is not in section 15.
  - Requirement 5 says "on the day the CNA record lands". Nothing in the design ties that to a feed schedule; section 2's evidence is CVEs published 2026-11-11 seen on 2026-11-13.
- **Axes:** the standing item is objective; the "exact" reading is contestable; remedies are Sam's choice.

### R9. No unit owns the product-set SQL, and the parity test's stated home cannot import a test database in-package

- **Lenses:** seams & contracts; downstream readiness.
- **Anchor:** section 12, "Parity (integration, `internal/check` with a test database)"; section 3.4, "`internal/check` exports what the compiler needs".
- **Claim:** Section 3.4 lists what `internal/check` exports: Go lookups, key builders and the two index-expression helpers. The SQL for the other-product exclusion (`starts_with`, the `!~ '^[[:alnum:]]'` test) and for the name terms is not in that list, so by default it is written in `internal/alert/dsl`. The parity test is placed in `internal/check`, which then has to reach SQL owned by another package, or `internal/check` has to own SQL the export list does not name. One side of this boundary is unstated.
- **Evidence:** `internal/testutil` imports `internal/store`, which imports `internal/check` (`go list` output; `internal/store/check.go:18`). A `package check` test that imports `testutil` is an import cycle, so the test must be `package check_test` and use only exported names; `internal/check` has no `TestMain` today (its test files are all unit tests), and `NewTestDB` fails without one (project CLAUDE.md). The export list covers "the rule behind `isOtherProduct`", so the test is feasible, but the plan author has to work out the package, the `TestMain`, and which package builds the SQL.
- **Axes:** objective; remedy determinate (name the owner of the SQL fragment and the test's package).

### R10. The two-arm package predicate is used where the ecosystems are already known

- **Lens:** simplicity & proportionality.
- **Anchor:** section 5.1, "`(cap.ecosystem = 'PyPI' AND <folded name> = ANY($pypiNames)) OR (cap.ecosystem <> 'PyPI' AND <folded name> = ANY($names))`".
- **Claim:** The only case the index serves is an `eq`/`in` ecosystem condition with exact values. In that case the compiler knows whether PyPI is among them and can emit one arm (`<folded name> = ANY($names)` with the values folded for those ecosystems). The two-arm `OR` is needed only when no ecosystem is given, which is the sequential-scan case anyway.
- **Evidence of current cost:** the document's own statements that the array form is unmeasured (section 5.3 last sentence; section 13 "expected to read `cve_affected_packages_check_idx`") and the release-arm note in section 5.1. The index-served path's plan depends on the planner combining a top-level `ecosystem = ANY` with two `OR` arms; the one-arm form is the shape already measured at 0.52 ms.
- **Axes:** contestable; remedy a choice.

### R11. Smaller places where a plan author must guess

- **Lens:** downstream readiness.
- **Anchor and evidence:**
  - Section 8, "`in` with no values | error": the row sits among the `affected.cpe_product` rows. Whether it applies to `affected.package in []` and to existing fields is unstated. Today `affected.ecosystem in []` passes validation (`validator.go:198-211`).
  - Section 11 lists no PLAN.md entry for the 50-product and 100-condition limits or the empty-`in` error, so `/plan-check` against §10 has nothing to check them against.
  - Section 10 adds one prompt line for the product field. It says nothing about telling the AI search prompt that ecosystem and package now correlate or that `affected.package` takes `eq`; a generated several-ecosystems rule matches nothing with no signal (section 8 note).
  - Section 5.3's table has no row where both forms ran the same query on a candidate path except realtime (0.34 ms against 0.28 ms). The batch rows compare Node in one column with `linux:linux_kernel` in the other. The set form's case rests on dry-run alone; that is enough for the choice, but the batch cost of the set form relative to today is unknown.
- **Axes:** objective; remedies determinate.

## Per-lens lines

- **Requirements trace:** R8 (standing: requirements completeness unverifiable — unpinned), R3.
- **Simplicity & proportionality:** R10. The 100-condition limit, the single `Where` form and the reuse of the name table are each paid for; no other finding.
- **Seams & contracts:** R1, R9.
- **Failure modes:** R1, R2, R4, R5, R7. Security: rule values reach SQL only as parameters and the LIKE arm is escaped; no new endpoint or authorization boundary; the one exposure is statement cost (R2).
- **Unstated assumptions:** R2 (warm-cache margin), R4 (database ctype), R5 (candidate array copies), R8 (feed latency).
- **Alternatives & rationale:** R2, and R4's ASCII-class alternative. Sections 3.6, 5.3 and 7 record their other alternatives with reasons.
- **Change & reversibility:** R6. Correlation and hash back-out are stated.
- **Downstream readiness:** R3, R1, R5, R9, R11. Pitfalls docs read: DB-12 is addressed in the text and its note; NOTIFY-2 applies to R7 and to open question 2's "neither"; ARCH-2 applies to section 4.1's exact ecosystem comparison, already carried by that section's note (rule values are canonical-case only, `ecosystem.Valid`, `internal/ecosystem/ecosystem.go:86-95`, so the risk is in stored values); testing-pitfalls §2 applies to R4; testing-pitfalls §4 is carried by the section 5.2 note; ARCH-47 and DB-22 are met by section 7's sort over both hashed fields.
