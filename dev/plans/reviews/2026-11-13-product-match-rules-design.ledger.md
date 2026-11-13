# Review ledger — 2026-11-13-product-match-rules-design

## Run 1 — 2026-11-13

### Run header (mutable — update at every phase transition)

- **Doc:** `dev/plans/2026-11-13-product-match-rules-design.md` · **baseline snapshot:** `ec239ff`
- **Mode:** light — **surface fired:** none — **evidence:** no schema migration, no new boundary between separately deployed, persisted or trust-separated systems, no concurrency or crash-recovery mechanism; the material-hash change in section 7 is an alert-dedupe semantics choice posed to Sam, not a data-integrity mechanism.
- **Requirements:** unpinned — section 1 paraphrases requirement MATCH-2 of the private homelab integration requirements and Sam has not confirmed that wording. This session was started by another session, not by Sam, so the confirmation question was not asked; requirements trace runs narrowed to internal consistency, and standing entry P0-1 routes completeness to the gate.
- **Repo tier:** 1 (git work tree on the session's own branch; committing allowed).
- **Current phase:** 0
- **Rounds** (logical dispatch and prospective ordinal written BEFORE LAUNCH, completed at return):

| Round | Route (reviewer · slice · scope · shape · context · model+effort · prompts vN) | Snapshot | Roster | Status | Breaker evidence |
|---|---|---|---|---|---|

- **Per-lens coverage** (one row per whole-doc round; cell = finding IDs or NSF):

| Round | requirements trace | unstated assumptions | alternatives & rationale | seams & contracts | failure modes | change & reversibility | downstream readiness | simplicity & proportionality |
|---|---|---|---|---|---|---|---|---|

- **Gate:** not posed
- **Breaker:** eligible after independently re-reviewed repair wave `not yet` · next backstop ordinal `1` · active trigger `none` · one-additional-read authorization `none` · in-flight `none`
- **Closure:** cold reader — pending · verifier — pending · pooled attempt — · live-vs-snapshot re-compare — pending
- Terminal state:

### Index (append-only rows; State cells edited in place)

| ID | Round | Lens(es) | Class | Disposition | State |
|---|---|---|---|---|---|
| P0-1 | P0 | requirements trace | genuine choice | confirmed | open — gate item |
| L1 | 1 | downstream readiness | documentary gap | confirmed | fixed |
| L2 | 1 | failure modes, seams & contracts | forced correction | confirmed | fixed |
| L3 | 1 | downstream readiness, change & reversibility | documentary gap | confirmed | fixed |
| L4 | 1 | alternatives & rationale | documentary gap | confirmed | fixed |
| L5 | 1 | unstated assumptions | documentary gap | confirmed | fixed |
| L6 | 1 | downstream readiness | forced correction | judged non-substantive — wording only; fixed anyway | fixed |
| L7 | 1 | change & reversibility | documentary gap | confirmed | fixed |

### Detail — P0-1

- **Anchor:** 1. Requirements — "Status: unconfirmed."
- **Claim:** requirements completeness cannot be checked: section 1 is a paraphrase Sam has not confirmed. · **Evidence:** the requirements document is private and must not be quoted in this public repository; the session that started this review is not Sam.
- **Axes:** objective · remedy choice (Sam confirms or corrects section 1) · records
- **Source raw:** Phase 0 standing entry
- **Action:** route to the gate as "confirm section 1 as the requirements" · **taken:** — · **Before:** — · **After:** —

### Detail — L1

- **Anchor:** 5.1 The CVE-set form — "AND NOT (...)                            -- the product's other products"
- **Claim:** the SQL form of the other-product exclusion is unstated; a prefix other-product ends at a word boundary in Go (`isOtherProduct`), and a plan author would have to invent the SQL rule. · **Evidence:** `internal/check/names.go` `isOtherProduct`: a prefix matches only when the rest of the product is empty or starts with a character that is not a letter or digit.
- **Axes:** objective · determinate · records — **source:** repo (`internal/check/names.go`)
- **Source raw:** pilot
- **Action:** state the rule under the SQL sketch, with the `.NET FrameworkExtensions` case. · **taken:** added a paragraph under the SQL sketch stating the exclusion rule and the two .NET cases · **Before:** (none) · **After:** "A row is one of the product's other products when its lower-cased vendor equals ..."

### Detail — L2

- **Anchor:** 7. Material hash and CNA product names — "lower-cased, trimmed CNA vendor and product"
- **Claim:** the hash normalisation trims spaces but the match does not (`lower(a.vendor)` against the index's untrimmed expression), so a trim-only change would move the hash without changing any match, and a hash equal across copies would hide a difference that changes a match. · **Evidence:** section 5.1 compares `lower(a.vendor)`; `cve_cna_affected_check_idx` is on `left(lower(vendor), 256)`.
- **Axes:** objective · determinate · repairs
- **Source raw:** pilot
- **Action:** hash the pairs exactly as the match compares them (lower case, not trimmed); drop the trimming sentence; say the 721 rows with surrounding spaces match no name. · **taken:** section 7 now hashes lower-cased, untrimmed pairs and says why · **Before:** "lower-cased, trimmed CNA vendor and product" · **After:** "lower-cased as the match compares them ... Spaces are not trimmed, because the match does not trim either"

### Detail — L3

- **Anchor:** 4.2 Correlation — "every `affected.package` condition and every `affected.ecosystem` condition with `eq` or `in` must hold for one `cve_affected_packages` row"
- **Claim:** a consequence is unstated: two package conditions in one `and` rule that no single name satisfies (`eq a` and `eq b`) can never match, and "a CVE affecting both a and b" is no longer expressible in one rule. · **Evidence:** follows from the rule as written.
- **Axes:** objective · determinate · records — **source:** session (derived from section 4.2's rule)
- **Source raw:** pilot
- **Action:** add the consequence and the way to say it (two rules, or `in`). · **taken:** added two sentences to section 4.2 · **Before:** (none) · **After:** "Two package conditions in one `and` rule must also hold on one row, so ... matches nothing"

### Detail — L4

- **Anchor:** 3. The `affected.cpe_product` field (no alternatives subsection)
- **Claim:** the field's shape has no recorded alternatives: separate `affected.vendor` and `affected.product` fields, or extending the CPE watchlist item to read CNA names. · **Evidence:** section 3 records rejected sources and operators, not rejected shapes.
- **Axes:** objective · determinate · records — **source:** session (alternatives weighed while designing)
- **Source raw:** pilot
- **Action:** add section 3.6 with the two alternatives and why each was rejected. · **taken:** added section 3.6 · **Before:** (none) · **After:** "### 3.6 Alternatives not chosen"

### Detail — L5

- **Anchor:** 3.5 Alert behaviour over a CVE's life — "The CVE is new, so its first `material_hash` runs realtime evaluation"
- **Claim:** assumes the first source to deliver the CVE carries the CNA entry; if another feed (OSV, KEV, GHSA) delivers it first, the CNA rows arrive on a later merge that may change nothing material. · **Evidence:** `internal/ingest/handler.go` runs realtime only on a hash change; CNA rows are not hash inputs.
- **Axes:** objective · determinate · records — **source:** repo (`internal/ingest/handler.go`, `internal/store/cve.go` `GetCVEMaterialHash` returns "" for a missing CVE)
- **Source raw:** pilot
- **Action:** add that case to step 1, pointing at step 4 and section 7. · **taken:** added one sentence to section 3.5 step 1 · **Before:** "and the rule fires." · **After:** "... If another feed (OSV, GHSA, KEV) delivered the CVE first without a CNA entry, the CNA rows arrive on a later merge, which is step 4's case."

### Detail — L6

- **Anchor:** 8. Validation and messages — "with no `affected.ecosystem` `eq` or `in` condition in an `and` rule, or in an `or` rule"
- **Claim:** the row's condition reads two ways. · **Evidence:** "in an `or` rule" can attach to "condition" or to the whole case.
- **Axes:** objective · determinate · repairs
- **Source raw:** pilot
- **Action:** rewrite as two plain cases. · **taken:** rewrote the case cell · **Before:** "with no `affected.ecosystem` `eq` or `in` condition in an `and` rule, or in an `or` rule" · **After:** "in an `or` rule, or in an `and` rule that has no `affected.ecosystem` condition with `eq` or `in`"

### Detail — L7

- **Anchor:** 7. Material hash and CNA product names — "Cost: the hash of every CVE with CNA rows"
- **Claim:** the back-out cost is unstated: reverting the hash input changes the same hashes back, with the same re-fire cost. · **Evidence:** section 7 states only the forward cost.
- **Axes:** objective · determinate · records — **source:** session (follows from section 7's mechanism)
- **Source raw:** pilot
- **Action:** add one sentence. · **taken:** added one sentence to section 7 · **Before:** (none) · **After:** "Reverting the change later moves the same hashes back, at the same cost."
