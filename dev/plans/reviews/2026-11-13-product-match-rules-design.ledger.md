# Review ledger — 2026-11-13-product-match-rules-design

## Run 1 — 2026-11-13

### Run header (mutable — update at every phase transition)

- **Doc:** `dev/plans/2026-11-13-product-match-rules-design.md` · **baseline snapshot:** `ec239ff`
- **Mode:** light — **surface fired:** none — **evidence:** no schema migration, no new boundary between separately deployed, persisted or trust-separated systems, no concurrency or crash-recovery mechanism; the material-hash change in section 7 is an alert-dedupe semantics choice posed to Sam, not a data-integrity mechanism.
- **Requirements:** unpinned — section 1 paraphrases requirement MATCH-2 of the private homelab integration requirements and Sam has not confirmed that wording. This session was started by another session, not by Sam, so the confirmation question was not asked; requirements trace runs narrowed to internal consistency, and standing entry P0-1 routes completeness to the gate.
- **Repo tier:** 1 (git work tree on the session's own branch; committing allowed).
- **Current phase:** 2
- **Rounds** (logical dispatch and prospective ordinal written BEFORE LAUNCH, completed at return):

| Round | Route (reviewer · slice · scope · shape · context · model+effort · prompts vN) | Snapshot | Roster | Status | Breaker evidence |
|---|---|---|---|---|---|
| 1 | Pilot — self-review (session), all lenses, whole doc | `ec239ff` | runner | complete | ineligible — self-review · ordinal — |
| 2 | Independent — dispatched subagent (Claude Opus 5.5, high; cross-provider Codex available but not used — light mode, SHOULD not REQUIRED), all lenses, whole doc, single agent, cold, prompts v4 | `39a4a13` | 1 agent, all lenses | dispatched → 1 of 1 returned | grouped as-raised substantive 15 · previous-wave repairs judged defective / independently reviewed 0/7 (pilot wave) · review-record substantive / total substantive 0/15 · backstop ordinal 1 · evaluation exempt (first independent round) |
| 3 | Self-review of the round 2 repair wave (session), all lenses, whole doc | `39a4a13` + working tree | runner | complete | ineligible — self-review · ordinal — |
| 4 | Independent — dispatched subagent (Claude Opus 5.5, high; cross-provider not used, as round 2), all lenses, whole doc, single agent, cold, prompts v4 | `2713b8b` | 1 agent, all lenses | dispatched → 1 of 1 returned | grouped as-raised substantive 14 · previous-wave repairs judged defective / independently reviewed 5/16 (L8, L12, L14, L15, L18) · review-record substantive / total substantive 0/14 · backstop ordinal 2 · evaluation: no trigger (plateau needs a second stalled round; recursion 31% < 33%) |
| 5 | Self-review of the round 4 repair wave (session), all lenses, whole doc (wave read as one diff) | `2713b8b` + working tree | runner | complete | ineligible — self-review · ordinal — |

- **Per-lens coverage** (one row per whole-doc round; cell = finding IDs or NSF):

| Round | requirements trace | unstated assumptions | alternatives & rationale | seams & contracts | failure modes | change & reversibility | downstream readiness | simplicity & proportionality |
|---|---|---|---|---|---|---|---|---|
| 1 | NSF (narrowed: unpinned; P0-1 standing) | L5 | L4 | NSF | L2 | L3, L7 | L1, L3, L6 | NSF |
| 2 | L14, L15, L23 (standing) | L8, L9, L16, L18, L12 | L11, L16, L15 | L13, L17, L12, L8 | L8, L9, L10, L16, L19, L20 | L10, L20, L21 | L12, L13, L14, L18, L22, L10 | L15, L11 |
| 3 | NSF (narrowed) | L24 | NSF | NSF | NSF | NSF | L25 | NSF |
| 4 | L27, L33, L40 (standing) | L28, L29, L31 | L28, L29, L30, L37 | L26, L32, L35 | L26, L28, L31, L32, L33, L37 | L36, L38 | L26, L33, L34, L36, L39 | L30 |
| 5 | NSF (narrowed) | L41 | NSF | NSF | NSF | NSF | NSF | NSF |

- **Gate:** not posed
- **Breaker:** eligible after round 4 (independent re-review of the rounds 2–3 repair wave) · next backstop ordinal `3` · active trigger `none` · one-additional-read authorization `none` · in-flight `none`
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
| L8 | 2 | failure modes, unstated assumptions, seams & contracts | forced correction | confirmed | fixed |
| L9 | 2 | failure modes, unstated assumptions | documentary gap | confirmed | fixed |
| L10 | 2 | failure modes, change & reversibility | forced correction | confirmed | fixed |
| L11 | 2 | alternatives & rationale, simplicity & proportionality | genuine choice | confirmed | escalated — folded into open question 2 |
| L12 | 2 | downstream readiness, seams & contracts | forced correction | confirmed | fixed |
| L13 | 2 | seams & contracts, downstream readiness | forced correction | confirmed | fixed |
| L14 | 2 | requirements trace (consistency), downstream readiness | forced correction | confirmed | fixed |
| L15 | 2 | requirements trace, simplicity & proportionality, alternatives & rationale | genuine choice (scope) + forced correction (false workaround) | confirmed | false sentence fixed; scope escalated as open question 6, doc carries the recommended option |
| L16 | 2 | failure modes, alternatives & rationale | forced correction | confirmed | fixed |
| L17 | 2 | seams & contracts | forced correction | confirmed | fixed |
| L18 | 2 | unstated assumptions, downstream readiness | forced correction | confirmed | fixed |
| L19 | 2 | failure modes | documentary gap | confirmed | fixed |
| L20 | 2 | change & reversibility, downstream readiness | forced correction | confirmed | fixed |
| L21 | 2 | change & reversibility | documentary gap | confirmed | fixed |
| L22 | 2 | downstream readiness | documentary gap | confirmed | fixed |
| L23 | 2 | requirements trace | — | duplicate of P0-1 | closed |
| L24 | 3 | unstated assumptions | forced correction | confirmed | fixed |
| L25 | 3 | downstream readiness | forced correction | judged non-substantive — sentence order only; fixed anyway | fixed |
| L26 | 4 | seams & contracts, failure modes, downstream readiness | forced correction | confirmed | fixed |
| L27 | 4 | requirements trace | forced correction | confirmed | fixed |
| L28 | 4 | unstated assumptions, alternatives & rationale | documentary gap | confirmed | fixed |
| L29 | 4 | unstated assumptions, alternatives & rationale | forced correction | confirmed | fixed |
| L30 | 4 | simplicity & proportionality | forced correction | confirmed | fixed |
| L31 | 4 | unstated assumptions, failure modes | documentary gap | confirmed | fixed |
| L32 | 4 | seams & contracts, requirements trace | forced correction | confirmed | fixed |
| L33 | 4 | requirements trace, failure modes, downstream readiness | forced correction | confirmed | fixed |
| L34 | 4 | downstream readiness | forced correction | confirmed | fixed |
| L35 | 4 | seams & contracts | forced correction | confirmed | fixed |
| L36 | 4 | change & reversibility, downstream readiness | forced correction | confirmed | fixed |
| L37 | 4 | alternatives & rationale, failure modes | documentary gap | confirmed | fixed |
| L38 | 4 | change & reversibility | documentary gap | confirmed | fixed |
| L39 | 4 | downstream readiness | forced correction | confirmed | fixed |
| L40 | 4 | requirements trace | — | duplicate of P0-1 | closed |
| L41 | 5 | unstated assumptions | forced correction | confirmed | fixed |

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

### Detail — L8

- **Anchor:** 3.2 Operators — "`in` takes 1 to 50 values."
- **Claim:** the 50-value cap is per condition; nothing bounds a rule, so a rule can exceed PostgreSQL's 65,535 bind parameters or make realtime planning slow, and a failing rule holds the batch cursor for every rule. · **Evidence:** `dsl.Parse` and `Validate` have no condition count; realtime runs synchronously in `internal/ingest/handler.go`.
- **Axes:** objective · determinate (a per-rule bound) · repairs
- **Source raw:** round-2-independent.md, local ID R1
- **Action:** cap values across all `affected.cpe_product` and `affected.package` conditions of one rule at 50; add a realtime planning measurement of a 50-value rule to section 13. · **taken:** section 3.2 now bounds a rule at 50 values across product and package conditions, with the reason; section 8 has the rule-level error; section 13 measures a 50-value rule · **Before:** "`in` takes 1 to 50 values." · **After:** "A rule holds at most 50 values across all its `affected.cpe_product` and `affected.package` conditions together ..." (parameter count re-derived: 6 ranges x 3 + 5 CNA names x 4 = 38 for `nodejs:node.js`)

### Detail — L9

- **Anchor:** 13. Measure during implementation
- **Claim:** activation time against the 15-minute zombie sweep is unmeasured: about 2,600 pages of 1,000 IDs leave about 346 ms per page. · **Evidence:** `SweepZombieActivations` fails jobs with `locked_at` older than 15 minutes; no heartbeat.
- **Axes:** objective · determinate · records — **source:** repo (`internal/alert/evaluator.go`)
- **Source raw:** round-2-independent.md, local ID R2
- **Action:** add an activation budget and measurement to section 13. · **taken:** section 13 gained the activation scan measurement and a 7-minute limit · **Before:** (none) · **After:** "a full activation scan of a 50-value rule: the scan must finish well inside the 15 minutes ..."

### Detail — L10

- **Anchor:** 7. Material hash and CNA product names — "the hash of every CVE with CNA rows (405,809 ...) changes"
- **Claim:** a new hash field handled like the existing slices (nil becomes `[]`) changes every CVE's hash, not only those with CNA rows; the sort order and the realtime cost of redelivered CVEs are unstated. · **Evidence:** `internal/merge/hash.go` turns nil slices into `[]`; no field has `omitempty` (runner re-read, lines 76-85).
- **Axes:** objective · determinate · repairs
- **Source raw:** round-2-independent.md, local ID R3
- **Action:** specify `omitempty` (as the range-data design did for `last_affected`), the sort order, and the realtime cost. · **taken:** section 7 specifies `omitempty`, the nil slice, the byte-order sort, and the realtime cost of each moved hash; section 12's hash test checks a CVE with no CNA rows keeps its hash · **Before:** "the sorted, distinct pairs of CNA vendor and product" · **After:** "tagged `json:\"affected_products,omitempty\"` and left nil when a CVE has no CNA rows ... sorted by vendor and then product in byte order" (evidence: `internal/merge/hash.go` lines 76-85 re-read)

### Detail — L11

- **Anchor:** 7. Material hash and CNA product names — "Recommendation: add the CNA product identity"
- **Claim:** a third option is unrecorded: a separate change signal that schedules evaluation for non-material match inputs without changing the dedupe key. · **Evidence:** section 7 weighs only two options.
- **Axes:** contestable · choice
- **Source raw:** round-2-independent.md, local ID R4
- **Action:** add the option to section 7 and to open question 2; Sam decides. · **taken:** section 7 gained the separate-signal alternative; open question 2 lists three options · **Before:** "2. **CNA product names in `material_hash`** (section 7). Recommended yes." · **After:** "2. **How a CNA product change gets evaluated** (section 7). Options: ..."

### Detail — L12

- **Anchor:** 4.1 Exact match — "`ecosystem.FoldedNameSQL(cap.ecosystem, cap.package_name)` against the same expression applied to the value"
- **Claim:** as described the exact match cannot use `cve_affected_packages_check_idx` (the value's folding refers to the row), and the correlated group's SQL is not given. · **Evidence:** `internal/store/check.go` folds names in Go per ecosystem to reach the index.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-2-independent.md, local ID R5
- **Action:** give the package group's SQL: names folded in Go per named ecosystem and compared with `ecosystem =`; the row-folding filter only without an ecosystem; bare distro names by prefix. · **taken:** section 5.1 gained the package set SQL and a predicate table; section 4.1 says ecosystems compare exactly and points to it · **Before:** "against the same expression applied to the value with the row's ecosystem" · **After:** "For each pair of ecosystem value and name, folded in Go with `ecosystem.FoldPackageName` ..."

### Detail — L13

- **Anchor:** 3.4 Product names, shared with the version check — "The table, `ProductRef` and the CPE value checks move"
- **Claim:** the key builders (`CPEKeyFor`, `cnaNameKey`, `cutRunes`, `nextPrefix`, rune limits) and the index-expression helpers (`cpeIndexExpr`, `cnaNameIndexExpr`, unexported in `internal/store`) are not in the move list, and `dsl` cannot import `store`. · **Evidence:** `internal/check/keys.go`, `internal/store/check.go` (runner re-read).
- **Axes:** objective · determinate · repairs
- **Source raw:** round-2-independent.md, local ID R6
- **Action:** add them to the move list, with `internal/store` importing them from `internal/product`. · **taken:** section 3.4 lists every moved item, including the index-expression helpers and why · **Before:** "The table, `ProductRef` and the CPE value checks move to a new package `internal/product`" · **After:** "A new package `internal/product` takes everything both callers need ..." (names checked in `internal/check/names.go`, `keys.go`, `internal/store/check.go`)

### Detail — L14

- **Anchor:** 3.1 Value — "so a product that one accepts the other also accepts"
- **Claim:** false: the check accepts unescaped `*` and `?` inside a value and refuses non-printable-ASCII before lower-casing; the rule refuses wildcards, and section 3.1 omits the ASCII rule. · **Evidence:** `internal/check/input.go` `parseCPE`.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-2-independent.md, local ID R7
- **Action:** state the printable-ASCII rule, and say the rule accepts a subset of what the check accepts. · **taken:** section 3.1 adds the printable-ASCII rule and states the subset relation · **Before:** "so a product that one accepts the other also accepts" · **After:** "So every product a rule accepts, the check accepts too."

### Detail — L15

- **Anchor:** 4.2 Correlation — "Two package conditions in one `and` rule must also hold on one row"
- **Claim:** package-to-package correlation is unrequested, and "a CVE that affects both needs two rules" is false: two rules each alert on either package. · **Evidence:** requirement 2 names ecosystem with package only.
- **Axes:** scope contestable · choice; the false sentence objective
- **Source raw:** round-2-independent.md, local ID R8
- **Action:** rewrite section 4.2 to correlate each package condition with the positive ecosystem conditions only (package conditions stay independent of each other), which keeps "both" expressible; add open question 6 with the stricter reading as the alternative. · **taken:** section 4.2 rewritten to correlate each package condition with the ecosystem conditions only; the false two-rules sentence removed; open question 6 added; section 12 tests two package conditions · **Before:** "\"a CVE that affects both\" needs two rules" · **After:** "so a rule can still ask for a CVE that affects both. This is the narrower of two readings; open question 6 has the other."

### Detail — L16

- **Anchor:** 5.1 The CVE-set form — "`neq` and `not_in` on `affected.ecosystem` compile to `cves.cve_id NOT IN (...)`"
- **Claim:** `NOT IN` degrades on the whole-corpus paths. · **Evidence:** runner measured on the kept ingest: `NOT IN` npm with severity critical, dry-run, hit the 60 s statement timeout; `NOT EXISTS`, 243 ms (m11 in the session notes).
- **Axes:** objective · determinate · repairs
- **Source raw:** round-2-independent.md, local ID R9
- **Action:** compile `neq` and `not_in` to `NOT EXISTS` (today's form), with the measurement. · **taken:** section 5.1 keeps `NOT EXISTS` with the measurement; section 5.3 gained the row; section 12's test says `NOT EXISTS` · **Before:** "compile to `cves.cve_id NOT IN (...)`" · **After:** "keep today's correlated `NOT EXISTS`, not `NOT IN`"

### Detail — L17

- **Anchor:** 5.1 — "This is the rule `check.isOtherProduct` applies today"
- **Claim:** the other-product rule exists in Go and in SQL with no parity test; they differ outside ASCII. · **Evidence:** Go uses `unicode.IsLetter`/`IsDigit`; SQL character classes depend on the database locale.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-2-independent.md, local ID R10
- **Action:** state the SQL test and add a parity test over every table entry plus non-ASCII cases. · **taken:** section 5.1 states the SQL class and the parity test; section 12 gained the parity test · **Before:** (none) · **After:** "In SQL the following character is tested with `!~ '^[[:alnum:]]'` ..."

### Detail — L18

- **Anchor:** 5.1 "Their dry-run gets faster"; 5.3 "because they hold host paths"
- **Claim:** "gets faster" generalises from the correlated case; `contains` with no ecosystem and the `ExecuteDSLQuery` shape are unmeasured; the query files hold no host paths. · **Evidence:** runner measured the saved-search shape for `linux:linux_kernel` at 357 ms (m11).
- **Axes:** objective · determinate · repairs
- **Source raw:** round-2-independent.md, local ID R11
- **Action:** narrow the claim, add the saved-search row, add the unmeasured case to section 13, correct the host-path sentence, note PostgreSQL 18 only. · **taken:** section 5.1 narrows the speed claim; section 5.3 gained the saved-search row and corrects the host-path sentence; section 2 notes PostgreSQL 18 only; section 13 measures `contains` with no ecosystem · **Before:** "Their dry-run gets faster" / "because they hold host paths" · **After:** "The correlated case got faster in the one comparison measured" / "read-only SQL kept in the shared session notes outside the repository"

### Detail — L19

- **Anchor:** 8. Validation — the no-ecosystem warning
- **Claim:** AI search acts only on blocking errors, so the warning never reaches its user. · **Evidence:** `internal/api/ai.go`.
- **Axes:** severity contestable · record determinate
- **Source raw:** round-2-independent.md, local ID R12
- **Action:** say so in section 5.3 beside the 10.5 s row. · **taken:** section 5.3 says AI search ignores warnings · **Before:** (none) · **After:** "but AI search acts only on validation errors (`internal/api/ai.go`), so a generated rule of that shape runs with no warning shown"

### Detail — L20

- **Anchor:** 4.3 Existing rules change meaning — "the batch path resolves the open event"
- **Claim:** realtime also resolves; open events from the old reading stay open until each CVE is next evaluated; section 11 omits PLAN.md §10.5 and §10.2's list of selective constraints. · **Evidence:** `evaluateRule` resolves with `suppressResolution=false` on realtime too.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-2-independent.md, local ID R13
- **Action:** correct section 4.3 and extend section 11. · **taken:** section 4.3 names realtime, batch and EPSS and says when old events resolve; section 11 gained §10.2 and §10.5 · **Before:** "the batch path resolves the open event" · **After:** "When a CVE that no longer matches is next evaluated (realtime on its next hash change, or a batch or EPSS run that includes it)"

### Detail — L21

- **Anchor:** 3.4 — "Adding a name to the table changes what existing rules and checks match, from their next evaluation"
- **Claim:** a rule sees a table edit only for CVEs evaluated afterwards; nothing back-fills. · **Evidence:** evaluation runs only on realtime, batch, EPSS and activation candidates.
- **Axes:** objective · determinate · records — **source:** repo (`internal/alert/evaluator.go`)
- **Source raw:** round-2-independent.md, local ID R14
- **Action:** say so. · **taken:** section 3.4 says a table edit reaches only CVEs evaluated afterwards · **Before:** "from their next evaluation" · **After:** "A table edit reaches a rule only for CVEs evaluated after it ships ... nothing re-evaluates the corpus for it."

### Detail — L22

- **Anchor:** 2 and 14 — "version check plan's Phase 2", "version check design's section 4.5"
- **Claim:** references name documents without paths. · **Evidence:** no path given.
- **Axes:** objective · determinate · records — **source:** repo (`dev/plans/`)
- **Source raw:** round-2-independent.md, local ID R15
- **Action:** add the paths. · **taken:** sections 2, 3.4 and 14 give the plan and design paths · **Before:** "version check plan's Phase 2" · **After:** "Phase 2 of the version check plan (`dev/plans/2026-11-09-version-check-endpoint-plan.md`"

### Detail — L23

- **Anchor:** 1. Requirements — "Status: unconfirmed."
- **Claim:** requirements completeness unverifiable — unpinned (standing finding). · **Evidence:** reviewer's standing line.
- **Axes:** objective · choice
- **Source raw:** round-2-independent.md, standing finding
- **Action:** none; duplicate of P0-1.

### Detail — L24

- **Anchor:** 3.2 Operators — "the 589 pairs filed under more than one part are the same product filed twice"
- **Claim:** unverified: the 589 pairs were counted, not inspected. · **Evidence:** runner's own measurement (m1) counts pairs only.
- **Axes:** objective · determinate · repairs
- **Source raw:** round 3 (runner)
- **Action:** replace the claim with what was measured and the direction of the error. · **taken:** rewrote the sentence · **Before:** "and the 589 pairs filed under more than one part are the same product filed twice" · **After:** "Matching every part can only add matches for the 589 pairs that NVD files under more than one part, which fails towards alerting."

### Detail — L25

- **Anchor:** 4.1 Exact match — "So `Foo_Bar` matches PyPI `foo-bar`"
- **Claim:** the example follows the ecosystem sentence instead of the folding sentence it illustrates. · **Evidence:** sentence order.
- **Axes:** objective · determinate · repairs
- **Source raw:** round 3 (runner)
- **Action:** move the example after the folding sentence. · **taken:** moved · **Before:** ecosystem sentence, then example · **After:** example, then ecosystem sentence

### Detail — L26

- **Anchor:** 3.2 Operators — "A rule holds at most 50 values across all its `affected.cpe_product` and `affected.package` conditions"
- **Claim:** the cap leaves out ecosystem values, which section 5.1 turned into per-value terms and per-pair terms, and conditions per rule are unbounded, so a rule can still pass 65,535 parameters (pitfall DB-12). The L8 and L12 repairs are defective here.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-4-independent.md, local ID R1
- **Action:** bind package names and ecosystem values as arrays (one parameter per list, as the compiler does today); keep per-value terms only for products; cap products at 50 per rule and conditions at 100 per rule; rewrite the package predicate table. · **taken:** section 3.2 now caps product values at 50 and conditions at 100, and binds package and ecosystem lists as arrays; section 5.1's package SQL and predicate table rewritten to array parameters; section 8 rows and section 12/13 updated · **Before:** "A rule holds at most 50 values across all its `affected.cpe_product` and `affected.package` conditions together" · **After:** "**At most 50 `affected.cpe_product` values per rule** ... **At most 100 conditions per rule** ... Package names and ecosystem values do not count towards the 50: they are bound as arrays"

### Detail — L27

- **Anchor:** 1. Requirements — "matches a Node CVE on the day the CNA record lands"
- **Claim:** section 1 restates the acceptance case with open question 1's substitution already applied; the requirement names the Brotli CVE.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-4-independent.md, local ID R2
- **Action:** restate the acceptance requirement with the Brotli CVE, pointing at section 2 and open question 1. · **taken:** section 1 item 5 restored · **Before:** "matches a Node CVE on the day the CNA record lands" · **After:** "matches the Brotli CVE (CVE-2026-111497) on the day the CNA record lands ... open question 1 proposes a Node-named CVE instead."

### Detail — L28

- **Anchor:** 7. Material hash and CNA product names — "Cost: the hash of every CVE with CNA rows ... changes on its next merge"
- **Claim:** the ongoing cost is unstated: every later CNA product edit re-fires every rule matching the CVE, and because both copies are kept, one edit can move the hash twice (once per copy).
- **Axes:** contestable severity · determinate record — **source:** repo (`internal/merge/resolve.go` `resolveCNAAffected` keeps every distinct copy)
- **Source raw:** round-4-independent.md, local ID R3
- **Action:** add the ongoing cost to section 7 and open question 2. · **taken:** section 7 cost paragraph and open question 2 gained the ongoing and double-move cost · **Before:** (none) · **After:** "After that, the cost continues: every later CNA product edit is a material change that re-fires every rule matching the CVE ... one edit can move the hash twice"

### Detail — L29

- **Anchor:** 3.3 Sources — "It holds NVD's platform CPEs (`vulnerable = false`) beside the vulnerable ones"
- **Claim:** incomplete: `cve_affected_cpes` also holds CPEs a CNA lists in its own record, MSRC product names and Red Hat CPEs; reading only the CNA-supplied ones is not weighed. · **Evidence:** `internal/feed/mitre/adapter.go` appends `affected[].cpes`; runner's m2 counted 5,162 CVEs with a non-NVD CPE 2.3 row and no NVD match.
- **Axes:** objective (description) · determinate · repairs
- **Source raw:** round-4-independent.md, local ID R4
- **Action:** correct the description; record why the CNA-supplied CPEs are not read (the table has no source column) with the 5,162 count. · **taken:** section 3.3 describes every source in `cve_affected_cpes` and why the CNA-supplied CPEs are not read · **Before:** "It holds NVD's platform CPEs (`vulnerable = false`) beside the vulnerable ones" · **After:** "It holds every CPE string any source names ... 5,162 CVEs have a CPE 2.3 row there that is not one of NVD's and no NVD match. But the table records no source"

### Detail — L30

- **Anchor:** 3.4 — "A new package `internal/product` takes everything both callers need"
- **Claim:** `internal/alert/dsl` can import `internal/check` directly (`internal/check` imports only `ecosystem` and `version`), so a new package and the move are unneeded; only the two index-expression helpers in `internal/store` must move, into `internal/check`. · **Evidence:** reviewer ran `go list -deps ./internal/check`.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-4-independent.md, local ID R5
- **Action:** replace the new package with exports from `internal/check` and move the two helpers there; sweep every mention of `internal/product`. · **taken:** section 3.4 rewritten: no new package; `internal/check` exports, the two store helpers move into it; sections 5.1, 12 and 16 swept (no `internal/product` remains) · **Before:** "A new package `internal/product` takes everything" · **After:** "The rule compiler (`internal/alert/dsl`) imports `internal/check` ... no code moves except" (evidence: `go list -deps ./internal/check` re-run by runner: ecosystem, version only)

### Detail — L31

- **Anchor:** 5.1 — "In SQL the following character is tested with `!~ '^[[:alnum:]]'`"
- **Claim:** character classes and `lower()` depend on the database locale, while the hash lower-cases in Go; the parity test runs on one locale and the measurements on PostgreSQL 18 only.
- **Axes:** contestable severity · determinate record — **source:** session
- **Source raw:** round-4-independent.md, local ID R6
- **Action:** state the assumption and its bounded effect (table names and rule values are ASCII, so only stored non-ASCII text varies); section 13 repeats the plan rows on the oldest PostgreSQL the project runs in CI if it is not 18. · **taken:** section 5.1 gained the locale paragraph; section 13 repeats rows on another PostgreSQL major if used · **Before:** (none) · **After:** "PostgreSQL's `lower()` and `[[:alnum:]]` follow the database's character type ..."

### Detail — L32

- **Anchor:** 3.1 Value — "So every product a rule accepts, the check accepts too."
- **Claim:** a product ending in a lone backslash passes the listed checks and escapes the prefix separator; the check refuses it. The L14 repair is defective.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-4-independent.md, local ID R7
- **Action:** refuse a component that ends in an unescaped backslash. · **taken:** section 3.1 refuses a trailing unescaped backslash and states why the check refuses it; section 8 row and section 12 test added · **Before:** "So every product a rule accepts, the check accepts too." · **After:** "and a trailing unescaped backslash, which in a full CPE escapes the next colon, so the check refuses that CPE for its component count (`splitCPE`). Every product a rule accepts, the check accepts too; the parser's tests run each refusal through both." (evidence: `internal/check/input.go` `splitCPE`, `escapedAsCPERequires` re-read)

### Detail — L33

- **Anchor:** 4.2 Correlation — "each `affected.package` condition must hold on one `cve_affected_packages` row together with every `affected.ecosystem` condition"
- **Claim:** three compile rules are unstated: several ecosystem conditions with one package condition, a rule with ecosystem conditions only, and whether absorbed ecosystem conditions are also emitted; `{ecosystem eq npm, ecosystem eq PyPI, package contains x}` would silently match nothing. The L15 repair is incomplete here.
- **Axes:** objective · determinate (one reading follows from section 4.2) · repairs
- **Source raw:** round-4-independent.md, local ID R8
- **Action:** state the three rules and add a validator warning for more than one `eq`/`in` ecosystem condition beside a package condition. · **taken:** section 4.2 gained four compile rules and the several-ecosystems example; section 8 warning and section 12 test added · **Before:** (none) · **After:** "As compile rules, for an `and` rule: 1. Each package condition becomes one set ..."

### Detail — L34

- **Anchor:** 12. Tests — "the CVE IDs from dry-run (no candidate IDs) equal the IDs from evaluating the corpus in 1,000-ID pages"
- **Claim:** `DryRun` returns a count and at most 10 sample IDs, so the test cannot get the dry-run ID list.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-4-independent.md, local ID R9
- **Action:** compare `store.ExecuteDSLQuery` paged to the end (no candidate IDs) against the alert events an activation scan writes (candidate pages). · **taken:** section 12's path-equivalence test compares `ExecuteDSLQuery` paged to the end with activation-scan events · **Before:** "the CVE IDs from dry-run (no candidate IDs)" · **After:** "the CVE IDs that `store.ExecuteDSLQuery` returns when paged to the end (no candidate IDs) equal the CVE IDs of the alert events an activation scan writes"

### Detail — L35

- **Anchor:** 5.2 Compiler and evaluator contract — "`CompiledRule.Where(candidateIDs []string) sq.Sqlizer`"
- **Claim:** the contract does not say what an empty, non-nil slice means; `queryCandidates` treats it as no filter.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-4-independent.md, local ID R10
- **Action:** state that an empty slice, like nil, means no candidate filter. · **taken:** section 5.2 states nil and empty both mean no filter · **Before:** (none) · **After:** "A nil or empty slice means no candidate filter, as `queryCandidates` already treats an empty list."

### Detail — L36

- **Anchor:** 5.3 — "kept in the shared session notes outside the repository"
- **Claim:** a later run cannot repeat the measurements like for like without the queries. The L18 repair is defective.
- **Axes:** objective · determinate · repairs
- **Source raw:** round-4-independent.md, local ID R11
- **Action:** add an appendix with the measured statements of the chosen form. · **taken:** added Appendix A with the measured statements; section 5.3 points to it · **Before:** "The measurement queries are read-only SQL kept in the shared session notes outside the repository" · **After:** "Appendix A holds the measured statements" (checked against the session's m7, m8, m10, m11 query files; the saved-search row's narrower ranges and name recorded)

### Detail — L37

- **Anchor:** 5.3 — "The 10.5 s row is the slow case"
- **Claim:** two alternatives are unrecorded: an index on the folded name alone, and expanding to the ecosystems present.
- **Axes:** contestable · determinate record — **source:** session (runner weighed both while designing)
- **Source raw:** round-4-independent.md, local ID R12
- **Action:** record both with reasons. · **taken:** section 5.3 records both rejected remedies · **Before:** (none) · **After:** "Two remedies were weighed and not chosen: an index on the folded name alone ... and expanding a missing ecosystem to the ecosystems present"

### Detail — L38

- **Anchor:** 7 and 4.3 — cost and reversal
- **Claim:** moving 405,809 hashes also bumps their `date_modified_canonical`, which API pollers and digests read as modified and the batch path evaluates; reverting the correlation change has no stated path.
- **Axes:** objective · determinate · records — **source:** repo (`date_modified_canonical` moves only with the hash, PLAN.md §5.3 and §10.3)
- **Source raw:** round-4-independent.md, local ID R13
- **Action:** add both. · **taken:** section 7 gained the `date_modified_canonical` cost; section 4.3 gained the revert path · **Before:** (none) · **After:** "Each moved hash also moves the CVE's `date_modified_canonical` ..." / "Without a version, reverting the correlation is a code revert"

### Detail — L39

- **Anchor:** 4.1 Exact match — "An empty value is refused."
- **Claim:** a whitespace-only value is not refused (testing-pitfalls §4).
- **Axes:** objective · determinate · repairs
- **Source raw:** round-4-independent.md, local ID R14
- **Action:** refuse empty and whitespace-only values; add to section 8 and the tests. · **taken:** section 4.1, section 8 and section 12 refuse whitespace-only values · **Before:** "An empty value is refused." · **After:** "An empty or whitespace-only value is refused."

### Detail — L40

- **Anchor:** 1. Requirements — "Status: unconfirmed."
- **Claim:** requirements completeness unverifiable — unpinned (standing finding).
- **Axes:** objective · choice
- **Source raw:** round-4-independent.md, standing finding
- **Action:** none; duplicate of P0-1.

### Detail — L41

- **Anchor:** 3.2 Operators — "100 is far above any rule seen"
- **Claim:** unverified: no rules were inspected. · **Evidence:** the kept ingest holds no rules; none were counted.
- **Axes:** objective · determinate · repairs
- **Source raw:** round 5 (runner)
- **Action:** state the bound as a judgment and give the derived worst-case parameter count. · **taken:** rewrote the sentence · **Before:** "the project has no users, and 100 is far above any rule seen." · **After:** "100 is a judgment, not a measurement ... under 3,000 parameters." (derived: 50 x ~40 + 100 x 4 = 2,400)

