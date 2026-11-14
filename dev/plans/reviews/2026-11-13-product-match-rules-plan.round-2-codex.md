# Plan review round 2: independent cross-model read (Codex, gpt-6.1-sol, high effort, cold)

Raw findings as returned, reviewing dev/plans/2026-11-13-product-match-rules-plan.md after round 1.

## Findings

1. **Location:** Task 3.1, “count distinct normalised values … across every … condition”; Task 3.2, “one … set” per condition.
   
   **Dimension:** Implementation pitfalls — parameter limits.
   
   **Claim:** The approved limits do not bound the prescribed SQL below PostgreSQL’s 65,535 parameters. Repeating 50 products containing underscores in both components across 100 conditions produces **125,000 parameters**, or **125,201 with candidates**.
   
   **Evidence:** A standalone construction produced a 118,929-byte rule with 50 distinct products and 100 conditions. `internal/check/names.go:185` produces four CNA names per such product. Task 3.2 prescribes nine CPE parameters plus sixteen CNA parameters per product, repeated independently per condition.
   
   **Suggested fix:** Specify compilation reuse that keeps accepted rules within the bind limit, and add this case to compiler verification and measurements. If a further acceptance limit is needed, take that concrete constraint to Sam.

2. **Location:** Task 2.4, “some value `w` drawn from any of the conditions … test `w` against each condition.”
   
   **Dimension:** Implementation pitfalls — unbounded validation work.
   
   **Claim:** The exact algorithm permits quadratic work on an ordinary API request. Two disjoint ecosystem lists can force billions of comparisons despite the condition limit.
   
   **Evidence:** A standalone implementation of the prescribed loop performed **22,501,500 comparisons** for an 87,987-byte request containing two 3,000-value lists. The equivalent 30,000-value lists occupy **937,987 bytes** and require **2,250,015,000 comparisons**. Values such as `Debian:a123` satisfy `internal/ecosystem/ecosystem.go:86`; the request fits the 1 MiB limit at `internal/api/server.go:235`. These are algorithm measurements, not Go latency measurements.
   
   **Suggested fix:** Specify an intersection algorithm over sorted or indexed prefix cones that avoids the cross-product scan. Include the large disjoint-list case in validation performance verification.

3. **Location:** Task 4.1, “`postgres://${user}:${password}@127.0.0.1…`”; Task 4.2, “`pgx.ParseConfig(url)`.”
   
   **Dimension:** Implementation pitfalls — credentials in output.
   
   **Claim:** Raw interpolation breaks connection strings containing URL delimiters and can disclose the password through parse errors.
   
   **Evidence:** The installed pgx v5.9.2 calls `url.Parse` at `pgconn/config.go:555`; `pgconn/errors.go:131` appends the underlying error verbatim. Go’s `net/url/url.go:40` includes the input URL in that error. Exact runner probe, requiring no database: call `pgx.ParseConfig("postgres://review:sentinel/pass@127.0.0.1:5432/db?sslmode=disable")` and inspect `err.Error()` for `sentinel/pass`.
   
   **Suggested fix:** Construct a configuration without credentials in its parseable string, then assign `User` and `Password` directly. Require secret-safe error reporting and verify it with delimiter-containing sentinel credentials.

4. **Location:** Task 3.3, “`OtherProductSQL("lower($1)", "lower($2)", others)` … build with squirrel `sq.Dollar`.”
   
   **Dimension:** Context gaps — incorrect interface composition.
   
   **Claim:** Explicit `$1`/`$2` inputs collide with the placeholders squirrel generates for other-product names, so this prescription cannot perform the intended parity comparison.
   
   **Evidence:** Installed squirrel v1.5.4’s `placeholder.go:88` starts numbering `?` replacements at one without reserving existing dollar placeholders. The exact probe `sq.Dollar.ReplacePlaceholders("(lower($1) = ? AND lower($2) = ?)")` yields `(lower($1) = $1 AND lower($2) = $2)`.
   
   **Suggested fix:** Put the tested vendor and product in a parameterized derived table, reference its columns from `OtherProductSQL`, and let squirrel number all parameters together.

5. **Location:** Task 2.1, “`return sq.Expr(sqlExpr+" <> ALL(?)", pq.Array(vals)), nil`.”
   
   **Dimension:** Implementation pitfalls — NULL handling.
   
   **Claim:** This changes accepted `not_in: null` rules from matching everything to matching nothing. The claimed preservation of existing behavior misses nil slices.
   
   **Evidence:** `internal/alert/dsl/validator.go:143` accepts JSON `null` when unmarshalling into `[]string`. Squirrel’s `expr.go:187` treats the resulting zero-length slice as its constant true expression for `NotEq`; pq v1.12.3’s `array.go:668` serializes a nil slice as SQL NULL. Consequently, the prescribed predicate becomes `<> ALL(NULL)`.
   
   **Suggested fix:** Normalize nil lists to non-nil empty slices after decoding. Verify both `null` and `[]`, including a nullable left-hand column, against the existing behavior.

6. **Location:** Task 4.1, “`docker exec … psql …` with a file whose first line is `SET default_transaction_read_only = on;`.”
   
   **Dimension:** Implementation pitfalls — kept-database protection.
   
   **Claim:** This connection does not satisfy Phase 4’s own startup read-only guarantee: protection begins after psql starts processing the script, startup files remain enabled, and the commands are not explicitly enclosed in a read-only transaction.
   
   **Evidence:** Compare the command at plan line 604 with the guarantees at line 597. The pre-flight command supplies neither startup `PGOPTIONS` nor `-X`; the harness’s later checks do not protect this separate connection.
   
   **Suggested fix:** Prescribe `docker exec -e PGOPTIONS="-c default_transaction_read_only=on" … psql -X -v ON_ERROR_STOP=1 …`, with explicit `BEGIN READ ONLY`. The runner should verify `SHOW transaction_read_only` inside that transaction before querying the corpus.

7. **Location:** Task 5.6, “the next `EvaluateBatch` evaluates the CVE through the `date_match_inputs_changed` branch.”
   
   **Dimension:** Testing pitfalls — another path can satisfy the assertion.
   
   **Claim:** The prescribed setup does not isolate the new branch. A first batch run scans everything; a recently ingested CVE also remains eligible through its material timestamp during the rescan window.
   
   **Evidence:** `internal/alert/evaluator.go:206` preserves a zero cursor for a full scan; lines 729–748 implement the full-scan and material-timestamp paths. The two-minute subtraction occurs at line 209. Task 5.6 requires neither a nonzero cursor nor an old material timestamp.
   
   **Suggested fix:** Establish a nonzero cursor and place `date_modified_canonical` outside its rescan window while leaving only the match-input timestamp eligible. Falsification probe: remove the second UNION arm temporarily and run `go test ./internal/alert -count=1 -run Recheck`; the recovery test must fail.

8. **Location:** Task 5.5, “Modify `internal/alert/evaluator.go`”; Task 5.6, “follow `internal/alert/late_binding_test.go`.”
   
   **Dimension:** Cross-task dependencies — existing fixture assumptions.
   
   **Claim:** Adding the timestamp branch invalidates `ageCorpus`, which existing tests use to prove that unchanged CVEs are outside ordinary batch selection. Those tests can then pass through the new branch while their intended mechanism is broken.
   
   **Evidence:** `internal/alert/watchlist_cve_test.go:153` ages only `date_modified_canonical` and `date_epss_updated`. Its caller at line 232 tests watchlist additions; `internal/alert/late_binding_test.go:138` uses it to isolate late-binding recovery. Phase 5 will leave their initial `date_match_inputs_changed` recent.
   
   **Suggested fix:** Add `ageCorpus` and its consumers to Task 5.5’s scope, age the new timestamp too, and assert that ordinary CVE selection is empty before exercising the alternate trigger.

9. **Location:** Task 4.2, “Activation estimate … per-insert median times the kept-ingest match count”; Task 4.3, “Every threshold passes … start Phase 5.”
   
   **Dimension:** Design fidelity — measurement gate.
   
   **Claim:** The estimate can pass without executing the full activation required by design section 13. A small testcontainer’s insertion median does not establish full-corpus activation time.
   
   **Evidence:** Design line 411 requires a full activation scan. `internal/alert/evaluator.go:514` performs production event insertion per match; `internal/store/alert_rule.go:339` opens a transaction and acquires the organization’s feed lock for each insertion. The plan measures those writes on a separate small database and requires a restored-copy run only when the estimate exceeds five minutes.
   
   **Suggested fix:** Keep the estimate as preliminary evidence, but require an actual full activation on a restored, disposable copy before declaring M8 passed. The kept database can remain strictly read-only.

Substantive findings: 9
