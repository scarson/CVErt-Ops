# Design: product conditions and correlated package conditions in alert rules (MATCH-2)

Date: 2026-11-13. Author: Claude, for Sam. Status: draft for Sam's review. No implementation code or migration exists.

Review ledger: `dev/plans/reviews/2026-11-13-product-match-rules-design.ledger.md`.

## 1. Requirements

Status: unconfirmed. Paraphrased from requirement MATCH-2 of the private homelab integration requirements; Sam has not confirmed this wording.

1. **Product field.** The alert rule language gets a field for a CPE vendor and product, so a rule can say "this product, with severity high or above" without a watchlist. Version conditions come later (requirement MATCH-3, not designed here).
2. **Correlation.** `affected.ecosystem` and `affected.package` are matched within one affected-package entry, not anywhere in the CVE.
3. **Exact match.** `affected.package` gets an exact-match operator.
4. **Watchlists.** The requirement's title names watchlists as well as rules; its text and acceptance case concern rules only.
5. **Acceptance.** A rule `{affected.cpe_product eq nodejs:node.js, severity in [critical, high]}` matches a Node CVE on the day the CNA record lands, before NVD has analysed it.

Why it matters: Node, PHP and .NET in runner tool caches are invisible to per-host scanners, so a rule on the product is the only alert for them, and NVD analyses only a minority of new CVEs within weeks (section 2).

## 2. Findings that shaped the design

Measured on 2026-11-13 against the complete ingest kept from the version check plan's Phase 2 (about 2.6 million CVEs; PostgreSQL 18), read-only. Code read at `dev` `5598af6`.

| Finding | Evidence | Consequence |
|---|---|---|
| The requirement's own example, the Brotli CVE CVE-2026-111497, cannot match `nodejs:node.js` from CNA data. Its CNA record names `Google` / `Brotli` only. NVD's later analysis lists `nodejs:node.js`, `microsoft:.net` and 90 other CPEs. | `cve_cna_affected` and `cve_cpe_matches` rows for that CVE. | Before NVD analysis, a library flaw bundled into a product is visible only under the library's name. The acceptance case needs a CVE whose CNA names Node (open question 1). |
| NVD analyses a minority of recent CVEs. Of 33,458 CVEs published in the 60 days to 2026-11-13, 32,525 have a CNA `affected[]` row and 7,664 have a vulnerable NVD CPE row. | Count over `cves.date_published`. | The CNA source is required for the field to work on new CVEs. |
| CNA-only CVEs usually carry a severity. Of the 24,861 CVEs in that window with CNA rows and no vulnerable NVD row, 22,733 have a severity and 11,805 are critical or high. | Severity comes from CNA or CISA ADP metrics in the MITRE record, or from the metrics NVD relays (`internal/feed/mitre/adapter.go` `applyCVSS`; `internal/feed/nvd/adapter.go`). | The acceptance rule's severity condition can match on day one. About 9% of such CVEs have no severity and would not. |
| Node CVEs exist that only the CNA names. 144 CVEs have a CNA row `nodejs` / `node`, `nodejs` or `node.js`; 187 have a vulnerable NVD `nodejs:node.js` row; 59 are found only through the CNA. On 2026-11-13, 15 Node CVEs published 2026-11-11 had CNA rows and no NVD row, all with a severity (for example CVE-2026-123866, HIGH). | Counts over both tables. | The acceptance case is reachable with a real record. |
| CNA spellings of Node also include `The Node.js Project` / `Node.js` (16 rows) and `Node.js` / `Node.js` (3 rows). All 19 are on CVEs from 2017 to 2024 that NVD has analysed. The version check endpoint's name table does not list them. | Count over `cve_cna_affected`. | Add them to the shared name table (section 3.4); today they change no match. |
| Reading every stored CPE (`cve_affected_cpes`) instead of NVD's vulnerable rows adds platform CPEs and almost no unanalysed CVEs. `apple:macos` goes from 3,508 CVEs to 7,504; `linux:linux_kernel` from 15,369 to 19,746; `microsoft:windows_10_1607` from 3,429 to 3,977. Of 12 products sampled, the extra CVEs include one that NVD has not analysed. | Per-product counts over both tables. | The field reads NVD's vulnerable rows (section 3.3). |
| 23,717 vulnerable CPE rows carry backslash escapes in the vendor or product (`\&`, `\@`, `\/`, `\$`). 589 vendor-and-product pairs appear under more than one CPE part. | `cve_cpe_matches`. | Values are written with CPE escapes (section 3.1), and the field matches every part (section 3.2). |
| CNA rows and CPE match rows are not `material_hash` inputs. A change to them alone runs no realtime evaluation and does not move `date_modified_canonical`, which the batch path follows. | `internal/merge/pipeline.go`, comment before `replaceVersionRanges`; `internal/ingest/handler.go` runs realtime only when the hash changes. | A CNA product change on an existing CVE is not evaluated until something material changes (section 7). |
| The per-row `EXISTS` form the compiler uses for `affected.*` today is fast for one CVE and slow for the whole corpus when two sources are combined with `OR`: 11.1 s for a dry-run against the default 14 s statement timeout. | `EXPLAIN ANALYZE`, section 5.3. | A different query shape (section 5). |
| `affected.package` has substring operators only, and each `affected.*` condition is its own `EXISTS`, so `{affected.ecosystem eq npm, affected.package contains lodash}` matches a CVE with an npm package `foo` and a PyPI package `lodash`. For Debian and `openssl`, 395 CVEs have one row with both; 443 match the two conditions separately with `contains`. | `internal/alert/dsl/compiler.go` `affectedSQL`; counts. | Requirements 2 and 3 (section 4). |
| The SPA has no alert rule editor. Rules are written through the API, the AI search translates natural language through a prompt built from the field registry, and saved searches run DSL through `store.ExecuteDSLQuery`. Rule conditions are opaque JSON in the OpenAPI document. | `web/src/views`; `internal/ai/schema.go`; `internal/store/dsl_executor.go`; `internal/api/alert_rules.go`. | No SPA work for rules (section 10). |

## 3. The `affected.cpe_product` field

### 3.1 Value

A value is `vendor:product`: the vendor and product components of a CPE 2.3 name, separated by an unescaped colon, for example `nodejs:node.js`, `php:php`, `f5:nginx_open_source`, `microsoft:.net`.

- Written as NVD writes them in `cpe_normalized`: a character other than a letter, digit, `.`, `-` or `_` is escaped with a backslash (`notepad\+\+`, `1und1:1\&1_online_storage`). A backslash before `.`, `-` or `_` is dropped, because NVD writes those bare.
- Compared in lower case. A value in any case is accepted and lower-cased at compile time; the stored rule keeps what the caller sent.
- Each component must be a literal: not empty, not `*` or `-`, and containing no unescaped `*` or `?`.
- At most 255 characters.

The checks are the version check endpoint's CPE rules (`internal/check/input.go`: `splitCPE`, `dropRedundantEscapes`, `literalCPEValue`, `escapedAsCPERequires`), moved with the name table to a package both can import (section 3.4), so a product that one accepts the other also accepts.

The field is named `affected.cpe_product`, as the requirement writes it, because its value is a CPE identity even when the match comes from a CNA record.

### 3.2 Operators

`eq` and `in`. `in` takes 1 to 50 values.

The value carries no CPE part (`a`, `o`, `h`), and the field matches all three. The requirement's example has no part, and the 589 pairs filed under more than one part are the same product filed twice.

`neq` and `not_in` are refused: "no source names this product" is a noise filter, a different need from the alerting use cases, and with name aliasing across two sources its meaning would need its own design. Text operators are refused: a substring of a CPE name has no index and no stable meaning across the two sources. Either can be added later without changing stored rules.

### 3.3 Sources

A CVE matches a product when either source names it:

1. **NVD:** a `cve_cpe_matches` row with `vulnerable = true` whose `cpe_normalized` starts with `cpe:2.3:<part>:<vendor>:<product>:` for any part, for any of the product's CPE spellings (section 3.4).
2. **CNA:** a `cve_cna_affected` row whose vendor and product, in lower case, equal one of the product's CNA names, or start with a prefix name, and are not one of the product's other products (section 3.4). Every stored copy is read: the MITRE record's and NVD's relay of it.

Not read:

- `cve_affected_cpes`. It holds NVD's platform CPEs (`vulnerable = false`) beside the vulnerable ones, which roughly doubles the matches for operating systems (section 2), and it gave no day-one gain in the sample. CPE watchlist items still read it (section 9).
- The version check's nearby names (a CNA row under the product's vendor whose product contains a fragment, such as `F5` / `NGINX Plus` for `f5:nginx`). The check endpoint uses them only to refuse a clean answer. Matching them in a rule would alert for other products of the same vendor. Open question 4.
- CNA `package_key`. That is a package identity, not a product (section 14).

The union is deliberate: an alert that fires from either source fails towards telling the user. A CNA entry for a product still matches after NVD's analysis leaves the product out, and the reverse.

### 3.4 Product names, shared with the version check

`internal/check/names.go` holds the table that maps a CPE product to its CNA spellings (`NamesFor`) and the CNA products that a name would wrongly find (`otherProducts`), with the rule that the CPE's own vendor and product, with `_` read as a space and also kept, are always names. That table is the version check design's section 4.5 (CNA spellings of six products: Node.js, PHP, nginx, .NET, PostgreSQL and Python).

The rule field uses the same table, so a rule and a check of one product read the same CNA rows. The table, `ProductRef` and the CPE value checks move to a new package `internal/product`; `internal/check` and `internal/alert/dsl` import it. Two rows are added to the Node row's names: `node.js` / `node.js` and `the node.js project` / `node.js` (section 2). Adding a name to the table changes what existing rules and checks match, from their next evaluation; the table's tests cover both callers.

### 3.5 Alert behaviour over a CVE's life

For a Node CVE such as CVE-2026-123866:

1. The CNA record arrives (MITRE, or NVD's relay before analysis). The CVE is new, so its first `material_hash` runs realtime evaluation, and the rule fires. If another feed (OSV, GHSA, KEV) delivered the CVE first without a CNA entry, the CNA rows arrive on a later merge, which is step 4's case.
2. NVD analyses the CVE and adds CPEs. `cve_affected_cpes` is a `material_hash` input, so the hash changes and the rule fires a second time for the same CVE. This is the existing meaning of a material change (PLAN.md §5.3, affected CPE set). It means two notifications per product CVE that NVD analyses later.
3. NVD flips a CPE between vulnerable and not vulnerable with the same criteria string. The hash does not change, so a rule that starts or stops matching because of the flip is not evaluated until the next material change. This gap is accepted: closing it would put the vulnerable flag into the hash, which changes the hash of every NVD-analysed CVE.
4. The CNA changes its product names, with nothing else material. Section 7.

### 3.6 Alternatives not chosen

- **Separate `affected.vendor` and `affected.product` fields**, correlated like the package fields. A vendor alone is not a usable key: the CNA and NVD spell vendors differently (`php group` against `php`, `the node.js project` against `nodejs`), so a vendor value would match one source and miss the other, and only the pair can go through the name table.
- **Extend the CPE watchlist item to read CNA names**, with no rule field. The requirement asks for a rule that works without a watchlist, and changing the CPE item would change what existing items match, including their platform CPEs (section 9).

## 4. Package conditions: exact match and correlation

### 4.1 Exact match

`affected.package` gains `eq` and `in` (1 to 50 values). A value matches a stored row when the folded names are equal: `ecosystem.FoldedNameSQL(cap.ecosystem, cap.package_name)` against the same expression applied to the value with the row's ecosystem, as the watchlist package match does. So `Foo_Bar` matches PyPI `foo-bar` and npm `foo_bar`, not npm `foo-bar`. An empty value is refused.

### 4.2 Correlation

Under `logic: and`, every `affected.package` condition and every `affected.ecosystem` condition with `eq` or `in` must hold for one `cve_affected_packages` row. `{affected.ecosystem eq Debian, affected.package eq openssl}` means "a Debian row (any release) for openssl". Two package conditions in one `and` rule must also hold on one row, so `{affected.package eq a, affected.package eq b}` matches nothing; "a CVE that affects a or b" is `affected.package in [a, b]`, and "a CVE that affects both" needs two rules.

- `affected.ecosystem` with `neq` or `not_in` stays a condition on the whole CVE: "the CVE has no row in this ecosystem". Read per row it would mean "some row in another ecosystem", which says nothing useful.
- Under `logic: or`, each condition is matched on its own, as today. "Npm, or a package named lodash" has no single row to correlate.
- `affected.cpe_product` is not correlated with package conditions. It reads different tables, and a rule that names both a product and a package asks for a CVE that has both.

### 4.3 Existing rules change meaning

An existing `and` rule with an ecosystem and a package condition matches fewer CVEs once this ships. On its next evaluation of a CVE that no longer matches, the batch path resolves the open event and sends a resolution notification ("no longer matches the rule's conditions"). PLAN.md §10.5 says a changed meaning bumps `dsl_version` and keeps the old compiler. This design does not: the project has no users, and keeping the uncorrelated reading would keep the wrong answer. Open question 5.

## 5. Query shape

### 5.1 The CVE-set form

Each product condition, and each correlated group of package conditions, compiles to a membership test on a set of CVE IDs:

```sql
cves.cve_id IN (
    SELECT m.cve_id FROM cve_cpe_matches m
    WHERE m.vulnerable
      AND m.cve_id = ANY($candidates)          -- only when the caller has candidate IDs
      AND ((left(m.cpe_normalized, 512) COLLATE "C" >= $lo1 AND left(m.cpe_normalized, 512) COLLATE "C" < $hi1
            AND starts_with(m.cpe_normalized, $prefix1))
        OR ...)                                -- one range per part and CPE spelling
    UNION ALL
    SELECT a.cve_id FROM cve_cna_affected a
    WHERE a.cve_id = ANY($candidates)          -- only when the caller has candidate IDs
      AND ((left(lower(a.vendor), 256) COLLATE "C" = $v1 AND left(lower(a.product), 256) COLLATE "C" = $p1
            AND lower(a.vendor) = $fullv1 AND lower(a.product) = $fullp1)
        OR ...)                                -- one term per CNA name; a range for a prefix name
      AND NOT (...)                            -- the product's other products
)
```

A row is one of the product's other products when its lower-cased vendor equals the other product's vendor, and its lower-cased product equals the other product's name or, for a prefix, starts with it and is followed by nothing or by a character that is neither a letter nor a digit. This is the rule `check.isOtherProduct` applies today: `.NET Framework 4.8` is excluded from `microsoft:.net`, `.NET FrameworkExtensions` is not.

`neq` and `not_in` on `affected.ecosystem` compile to `cves.cve_id NOT IN (...)`; `cve_id` is `NOT NULL` in every child table, so `NOT IN` cannot meet a NULL. Ranges, prefixes and names are built in Go from `internal/product` (as `check.CPEKeyFor` and `cnaNameKey` build them today) and passed as parameters, never concatenated.

Two details are load-bearing, from the measurements in section 5.3:

- **Candidate IDs inside the set.** Realtime, batch, EPSS and activation pass candidate IDs. Without them inside each branch, the set for a large product is built in full for each evaluation (283 ms for `linux:linux_kernel` against one CVE); with them, 0.28 ms.
- **Ranges and names as `OR`-ed predicates, not a join to `unnest()` arrays.** With the join, the planner chose a sequential scan of `cve_cpe_matches` (7.7 to 13.9 s under `and`, over 60 s under `or`); with `OR`-ed predicates it uses a bitmap `OR` over `cve_cpe_matches_check_idx` (2.6 ms for Node).

This also changes how today's `affected.ecosystem` and `affected.package` compile, because correlation needs one set per group. Their dry-run gets faster: `npm` and `contains lodash` on one row takes 0.88 s, against 4.7 s for today's `contains lodash` alone.

### 5.2 Compiler and evaluator contract

`CompiledRule.SQL` becomes a method, `CompiledRule.Where(candidateIDs []string) sq.Sqlizer`, because the set's SQL depends on the caller's candidate IDs. Callers:

| Caller | Candidate IDs |
|---|---|
| `alert.Evaluator.queryCandidates` (realtime, batch, EPSS, activation) | its own list |
| `alert.Evaluator.DryRun`, `store.ExecuteDSLQuery` (saved searches, AI search) | none |

`queryCandidates` keeps appending `cves.cve_id = ANY(?)` itself; the set repeats the same list. The rule cache keeps caching `CompiledRule`. The watchlist pre-filter (`watchlistExpr`) is unchanged.

### 5.3 Measurements

`EXPLAIN ANALYZE` on the complete ingest, PostgreSQL 18, warm cache unless stated. "Batch" is the 5,000 most recently modified CVEs as candidates. The default statement timeout is 14 s (`DB_STATEMENT_TIMEOUT_MS`).

| Query | Per-row `EXISTS` form | CVE-set form, candidate IDs inside |
|---|---|---|
| Realtime, one CVE, `linux:linux_kernel` (largest product: 15,369 CVEs), `and` | 0.34 ms | 0.28 ms |
| Realtime, one CVE, `linux:linux_kernel`, `or` with `in_cisa_kev` | not measured | 0.34 ms |
| Batch, `nodejs:node.js`, `and` | 154 ms | not measured |
| Batch, `linux:linux_kernel`, `and` / `or` | not measured | 447 ms / 93 ms |
| Dry-run, `nodejs:node.js` and severity critical or high, `and` | 11.1 s | 2.6 ms |
| Dry-run, `nodejs:node.js` alone | not measured (each of 2.6 M rows probes both tables) | 15 ms |
| Dry-run, `nodejs:node.js` `or` `in_cisa_kev` | not measured | 1.32 s |
| Dry-run, `linux:linux_kernel` alone / `or` `in_cisa_kev` | not measured | 0.85 s / 1.23 s |
| Dry-run, `Debian` and `openssl` correlated | not applicable | 0.90 s |
| Dry-run, `affected.package eq openssl`, no ecosystem | not applicable | 10.5 s |

Realtime evaluates every active rule against each CVE whose hash changed, so its cost per rule is what matters at ingest; under 1 ms per product rule adds little to a merge that takes milliseconds. The last row is the one slow case: a package name with no ecosystem cannot use `cve_affected_packages_check_idx`, whose first column is the ecosystem. The validator warns about it (section 8). The measurement queries are kept with the session notes, not in the repository, because they hold host paths; the implementation plan repeats the realtime and dry-run rows on the kept ingest after the code exists.

## 6. Indexes

None are added. The CVE-set form uses indexes that exist:

| Index | Used by |
|---|---|
| `cve_cpe_matches_cve_id_idx`, `cve_cna_affected_cve_id_idx`, `cve_affected_packages_cve_id_idx` | Candidate IDs inside the set (realtime, batch, EPSS, activation) |
| `cve_cpe_matches_check_idx` on `left(cpe_normalized, 512) COLLATE "C"` | CPE prefix ranges, whole corpus |
| `cve_cna_affected_check_idx` on `left(lower(vendor), 256)`, `left(lower(product), 256)`, `COLLATE "C"` | CNA names, whole corpus |
| `cve_affected_packages_check_idx` on `(ecosystem, folded name)` | Exact package match with an ecosystem |

So the realtime path pays no new write cost: merge already maintains all of these.

## 7. Material hash and CNA product names

A rule now matches on CNA product names, which are not a `material_hash` input. A CNA that corrects `n/a` to a real product, or renames one, with nothing else material, does not run realtime evaluation and does not move `date_modified_canonical`, so the batch path does not see it either. The rule misses that CVE until its next material change.

**Recommendation: add the CNA product identity to `material_hash`.** `MaterialFields` gains `affected_products`: the sorted, distinct pairs of CNA vendor and product, lower-cased as the match compares them, with a missing value as an empty string. PLAN.md §5.3 already treats "what is affected" as material (packages and the CPE set); this adds the CNA's statement of it. Lower-casing keeps the NVD relay and the MITRE copy of one entry from moving the hash when they differ only in case. Spaces are not trimmed, because the match does not trim either: the 721 stored rows with surrounding spaces match no name, and a change to their spacing changes no match.

Cost: the hash of every CVE with CNA rows (405,809 of about 2.6 million) changes on its next merge. On an instance with active rules, each such CVE that matches a rule fires once more at its new hash, spread over the weeks in which feeds deliver those CVEs again; an OSV backfill would deliver most of them at once. The golden material hashes are regenerated in the same pull request. With no users this is accepted, but Sam's own instances may have rules. Reverting the change later moves the same hashes back, at the same cost. Open question 2.

Without it, section 3.5's step 4 stays a documented gap.

## 8. Validation and messages

Errors stop a save; warnings are returned with a valid rule. Messages follow the existing `ValidationError` list (`internal/alert/dsl/validator.go`), one entry per problem, with the condition index.

| Case | Severity | Message |
|---|---|---|
| `affected.cpe_product` value without exactly one unescaped colon, or an empty part | error | `value must be "vendor:product", the vendor and product of a CPE 2.3 name, for example "nodejs:node.js"` |
| Part is `*` or `-`, or holds an unescaped `*` or `?` | error | `vendor and product must be literal names, not "*", "-" or a pattern with "*" or "?"` |
| Unescaped character that CPE 2.3 requires escaped | error | `character "+" must be escaped with a backslash, as NVD writes CPE names (for example "notepad\+\+")`, naming the first such character |
| Over 255 characters | error | `value must not exceed 255 characters` |
| `in` with 0 or more than 50 values (either field) | error | `value must list 1 to 50 items` |
| An operator other than `eq` or `in` on `affected.cpe_product` | error | the existing `operator %q is not valid for field %q` |
| A product with no row in the name table | warning | `no other CNA spelling is known for "x:y"; before NVD analyses a CVE, it matches only if the CNA record names vendor "x" and product "y"` (with `_` shown as a space where the own names do) |
| `affected.package` `eq` or `in` with an empty value | error | `value must not be empty` |
| `affected.package` `eq` or `in` in an `or` rule, or in an `and` rule that has no `affected.ecosystem` condition with `eq` or `in` | warning | `without an ecosystem condition in an "and" rule, this match cannot use an index, so dry-run and saved searches can be slow` |

`affected.cpe_product` joins `selectiveFields`, so a regex rule with a product condition is allowed without a watchlist. The validator needs no database; the warning about unmapped products comes from the table in code.

## 9. Watchlists

**Recommendation: no new watchlist item type in this work.** `affected.cpe_product in [...]` lists a lab's products in one rule, which is what the requirement's text asks for. A product item type (`item_type = 'product'`, a `vendor:product` column, matched by the same set SQL as the rule field) would let one list feed several rules and digests, which PLAN.md §9.1 anticipates ("vendors/products, optional convenience"). It needs a migration, API and SPA changes to the watchlist views. Open question 3.

Interaction with the existing CPE item, which stays as it is: a CPE item matches `cve_affected_cpes` by prefix, including NVD platform CPEs and with no CNA names, while the rule field reads NVD's vulnerable rows and CNA names. A rule bound to a CPE-item watchlist and using the field gets the intersection of the two. The field's description in PLAN.md says how the two differ, so a user does not expect them to agree.

## 10. Frontend, AI search and API description

- **SPA:** no change. There is no rule editor, and the CVE detail page's affected section is not part of this work.
- **AI search:** the prompt lists every registered field from `ExportFieldDescriptions`, so the new field and operators appear without code, and `PromptVersion` changes. One line is added to the prompt's notes: `affected.cpe_product` takes `vendor:product` from a CPE name, such as `nodejs:node.js`. `FieldDescription.TypeDesc` for the field is `"CPE vendor:product"`.
- **OpenAPI:** no change; rule conditions are JSON the spec does not enumerate. `schema.d.ts` is not regenerated.

## 11. PLAN.md changes

- §10.1: add `affected.cpe_product` (CPE `vendor:product`; NVD vulnerable CPE rows and CNA names) and note that `affected.ecosystem` and `affected.package` are matched on one row under `and`.
- §10.2: `affected.package` takes `eq` and `in`, compared after package-name folding.
- §5.3, if open question 2 is accepted: the CNA product set is material.
- Appendix A's `cve_cpe_matches` and `cve_cna_affected` entries: alert rules read them.

## 12. Tests

TDD per the project rules. Integration tests use testcontainers through `testutil.NewTestDB`.

**Unit (`internal/alert/dsl`, `internal/product`):**

- Value parsing: valid values from section 2's escaped rows (`1und1:1\&1_online_storage`), `\.` dropped, uppercase lower-cased, each error row of section 8, 255 and 256 characters, `in` with 0, 1, 50 and 51 values.
- The unmapped-product warning appears for `example:widget` and not for `nodejs:node.js`.
- `internal/product` keeps the version check's existing name tests, plus the two new Node names.

**Integration with `testutil.SeedCorpus`** (71 records). The golden NVD page holds CVE-2026-56847 (CNA `nodejs` / `node` and NVD `nodejs:node.js`), CVE-2026-111497 (CNA `Google` / `Brotli`, NVD lists Node) and CVE-2026-107832 (`Awaiting Analysis`, CNA `fastify` / `fastify` only, with a CVSS metric).

- A rule `{affected.cpe_product eq fastify:fastify, severity in [critical, high, medium]}` matches CVE-2026-107832 with no NVD row; this is the seeded form of the acceptance case. The test asserts the severity it relies on.
- `nodejs:node.js` matches CVE-2026-56847 and CVE-2026-111497; `google:brotli` matches CVE-2026-111497 from both sources.
- **Same answer on every path:** for a set of rules (each section 3 and 4 shape, `and` and `or`), the CVE IDs from dry-run (no candidate IDs) equal the IDs from evaluating the corpus in 1,000-ID pages, as activation does. This is the guard on section 5.2's two forms of one rule.

**Integration with hand-built patches** (`feed.CanonicalPatch`, run through the merge pipeline):

- The acceptance case: a copy of CVE-2026-56847's CNA entry with no NVD configuration and severity `HIGH`, ingested so realtime runs; the rule fires. Then an NVD patch adds `nodejs:node.js`: the hash changes and the rule fires a second time (section 3.5).
- A CVE whose only Node CPE is `vulnerable: false` does not match.
- CNA `Node.js` / `Node.js` and `The Node.js Project` / `Node.js` match `nodejs:node.js`.
- `.NET 9.0 runtime` matches `microsoft:.net`; `.NET Framework 4.8` and `OpenAPI.NET` do not; `.NET FrameworkExtensions` does.
- A CNA vendor of 300 characters whose first 256 equal a table name does not match (the full-name recheck).
- A rejected CVE with a matching product does not match.
- Correlation: a CVE with npm `foo` and PyPI `lodash`. `{ecosystem eq npm, package eq lodash}` under `and` does not match; under `or` it does; `{ecosystem eq PyPI, package eq lodash}` matches.
- Folding: `package eq Foo_Bar` matches PyPI `foo-bar`, not npm `foo-bar`.
- `ecosystem eq Debian` with `package eq openssl` matches a `Debian:13` row; `ecosystem neq npm` with `package eq lodash` is a CVE-level `NOT IN` and does not match a CVE that also has any npm row.
- If open question 2 is accepted: a CNA product change alone moves `material_hash` and fires realtime; a case-only or space-only difference between two copies does not. Golden hashes regenerated in one commit.
- Late-binding: after a CVE ID move, a product rule matches the new ID (the CNA and CPE match rows move with it).

## 13. Measure during implementation

On the kept complete ingest, with the built code: the section 5.3 rows for realtime (one CVE, `linux:linux_kernel`), batch (5,000 IDs) and dry-run (Node, `linux:linux_kernel`, an `in` of 50 table-mapped and unmapped products, including planning time), and the dry-run of `affected.package eq` with no ecosystem. A realtime row over 5 ms, or a dry-run over 5 s other than the no-ecosystem package row, goes back to Sam before merge.

## 14. Not in scope

- Version conditions in rules (requirement MATCH-3).
- CNA `package_key` for `affected.package`. 3,905 CVEs have a CNA package key and no package row under that CVE, 573 of them with no GHSA or OSV source at all (version check plan, Phase 4 notes). A package rule could read them, but that changes what "package" means for a rule; a later change can add it.
- `neq` and `not_in` on `affected.cpe_product` (section 3.2).
- NVD's vulnerable flag in `material_hash` (section 3.5).
- Showing CNA rows on the CVE detail page.

## 15. Open questions for Sam

1. **Acceptance case.** The requirement's example, the Brotli CVE, names only `Google` / `Brotli` in its CNA record, so no CNA-based rule for Node can match it before NVD analysis. Proposed acceptance: a Node CVE whose CNA names Node (CVE-2026-123866 live; a CNA-only copy of CVE-2026-56847 in tests). For bundled-library advisories like Brotli, the day-one rule names the library (`google:brotli`). Accept?
2. **CNA product names in `material_hash`** (section 7). Recommended yes. Cost: one more alert per matching CVE with CNA data on instances that already have rules, as feeds redeliver those CVEs.
3. **Watchlist product item type** (section 9). Recommended later, as its own change, if a rule's `in` list is not enough.
4. **Nearby CNA names** (section 3.3). Recommended no: a rule on `f5:nginx` would also alert for NGINX Plus and other F5 nginx products before NVD analysis. Yes would trade that noise for the CNA spellings the table does not know.
5. **No `dsl_version` bump for correlation** (section 4.3). Recommended no bump: existing `and` rules with an ecosystem and a package condition narrow, and their CVEs that stop matching send resolution notifications.

## 16. Delivery

One pull request to `dev`, in commits: move the CPE checks and name table to `internal/product` with the two names added; the CVE-set form and `CompiledRule.Where` with the package correlation and `eq`/`in`; `affected.cpe_product`; the material hash change if accepted, with golden hashes; PLAN.md. `/pitfall-check` before the evaluator commit, `/plan-check` against PLAN.md §10 before merge.
