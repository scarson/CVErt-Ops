# Design: product conditions and correlated package conditions in alert rules (MATCH-2)

Date: 2026-11-13. Author: Claude, for Sam. Status: approved for planning. Sam answered its two questions on 2026-11-13 (section 15.1). No implementation code or migration exists.

Review ledger: `dev/plans/reviews/2026-11-13-product-match-rules-design.ledger.md`.

Review record: the first review run stopped after 6 rounds (three independent rounds found 15, 14 and 11 defects), with 11 open findings noted in place. A second run, an independent review by Claude Fable at Sam's request followed by a discussion of its disputed findings, resolved all 11 notes and its own 11 findings, and the same reviewer then checked the fixes twice (10 problems, then 1, all fixed): each item is fixed in the text or was put to Sam. Sam then ruled on the two questions only he could answer, and section 15 records his rulings and every decision the design took itself. The last one-line fix, and the rewrite of sections 7 and 15 for Sam's rulings, had no further independent check; defects found while building come back to this document as findings.

## 1. Requirements

Status: confirmed by Sam on 2026-11-13 ("Q1. yes."), including the reading of "exact match" in item 3 and the substituted acceptance case in item 5. Paraphrased from requirement MATCH-2 of the private homelab integration requirements.

1. **Product field.** The alert rule language gets a field for a CPE vendor and product, so a rule can say "this product, with severity high or above" without a watchlist. Version conditions come later (requirement MATCH-3, not designed here).
2. **Correlation.** `affected.ecosystem` and `affected.package` are matched within one affected-package entry, not anywhere in the CVE.
3. **Exact match.** `affected.package` gets an exact-match operator. This design reads "exact" as equal after the ecosystem's own name folding (section 4.1; confirmed by Sam, section 15.1).
4. **Watchlists.** The requirement's title names watchlists as well as rules; its text and acceptance case concern rules only.
5. **Acceptance.** A rule `{affected.cpe_product eq nodejs:node.js, severity in [critical, high]}` matches the Brotli CVE (CVE-2026-111497) on the day the CNA record lands, before NVD has analysed it. Section 2 shows that this CVE's CNA record does not name Node; section 15.2 ("Acceptance case") substitutes a Node CVE whose CNA record names Node. "On the day the CNA record lands" also depends on how often the MITRE and NVD feeds are polled, which this design does not change.

Why it matters: Node, PHP and .NET in runner tool caches are invisible to per-host scanners, so a rule on the product is the only alert for them, and NVD analyses only a minority of new CVEs within weeks (section 2).

## 2. Findings that shaped the design

Measured on 2026-11-13 against the complete ingest kept from Phase 2 of the version check plan (`dev/plans/2026-11-09-version-check-endpoint-plan.md`; about 2.6 million CVEs; PostgreSQL 18), read-only. The project supports PostgreSQL 15 and later; plans were measured on 18 only. Code read at `dev` `5598af6`.

| Finding | Evidence | Consequence |
|---|---|---|
| The requirement's own example, the Brotli CVE CVE-2026-111497, cannot match `nodejs:node.js` from CNA data. Its CNA record names `Google` / `Brotli` only. NVD's later analysis lists `nodejs:node.js`, `microsoft:.net` and 90 other CPEs. | `cve_cna_affected` and `cve_cpe_matches` rows for that CVE. | Before NVD analysis, a library flaw bundled into a product is visible only under the library's name. The acceptance case needs a CVE whose CNA names Node (section 15.2, "Acceptance case"). |
| NVD analyses a minority of recent CVEs. Of 33,458 CVEs published in the 60 days to 2026-11-13, 32,525 have a CNA `affected[]` row and 7,664 have a vulnerable NVD CPE row. | Count over `cves.date_published`. | The CNA source is required for the field to work on new CVEs. |
| CNA-only CVEs usually carry a severity. Of the 24,861 CVEs in that window with CNA rows and no vulnerable NVD row, 22,733 have a severity and 11,805 are critical or high. | Severity comes from CNA or CISA ADP metrics in the MITRE record, or from the metrics NVD relays (`internal/feed/mitre/adapter.go` `applyCVSS`; `internal/feed/nvd/adapter.go`). | The acceptance rule's severity condition can match on day one. About 9% of such CVEs have no severity and would not. |
| Node CVEs exist that only the CNA names. 144 CVEs have a CNA row `nodejs` / `node`, `nodejs` or `node.js`; 187 have a vulnerable NVD `nodejs:node.js` row; 59 are found only through the CNA. On 2026-11-13, 15 Node CVEs published 2026-11-11 had CNA rows and no NVD row, all with a severity (for example CVE-2026-123866, HIGH). | Counts over both tables. | The acceptance case is reachable with a real record. |
| CNA spellings of Node also include `The Node.js Project` / `Node.js` (16 rows) and `Node.js` / `Node.js` (3 rows). All 19 are on CVEs from 2017 to 2024 that NVD has analysed. The version check endpoint's name table does not list them. | Count over `cve_cna_affected`. | Add them to the shared name table (section 3.4); today they change no match. |
| Reading every stored CPE (`cve_affected_cpes`) instead of NVD's vulnerable rows adds platform CPEs and almost no unanalysed CVEs. `apple:macos` goes from 3,508 CVEs to 7,504; `linux:linux_kernel` from 15,369 to 19,746; `microsoft:windows_10_1607` from 3,429 to 3,977. Of 12 products sampled, the extra CVEs include one that NVD has not analysed. | Per-product counts over both tables. | The field reads NVD's vulnerable rows (section 3.3). |
| 23,717 vulnerable CPE rows carry backslash escapes in the vendor or product (`\&`, `\@`, `\/`, `\$`). 589 vendor-and-product pairs appear under more than one CPE part. | `cve_cpe_matches`. | Values are written with CPE escapes (section 3.1), and the field matches every part (section 3.2). |
| CNA rows and CPE match rows are not `material_hash` inputs. A change to them alone runs no realtime evaluation and does not move `date_modified_canonical`, which the batch path follows. | `internal/merge/pipeline.go`, comment before `replaceVersionRanges`; `internal/ingest/handler.go` runs realtime only when the hash changes. | Section 7 adds a separate re-check signal for these inputs, decided by Sam. |
| The per-row `EXISTS` form the compiler uses for `affected.*` today is fast for one CVE and slow for the whole corpus when two sources are combined with `OR`: 11.1 s for a dry-run against the default 14 s statement timeout. | `EXPLAIN ANALYZE`, section 5.3. | A different query shape (section 5). |
| `affected.package` has substring operators only, and each `affected.*` condition is its own `EXISTS`, so `{affected.ecosystem eq npm, affected.package contains lodash}` matches a CVE with an npm package `foo` and a PyPI package `lodash`. For Debian and `openssl`, 395 CVEs have one row with both; 443 match the two conditions separately with `contains`. | `internal/alert/dsl/compiler.go` `affectedSQL`; counts. | Requirements 2 and 3 (section 4). |
| The SPA has no alert rule editor. Rules are written through the API, the AI search translates natural language through a prompt built from the field registry, and saved searches run DSL through `store.ExecuteDSLQuery`. Rule conditions are opaque JSON in the OpenAPI document. | `web/src/views`; `internal/ai/schema.go`; `internal/store/dsl_executor.go`; `internal/api/alert_rules.go`. | No SPA work for rules (section 10). |

## 3. The `affected.cpe_product` field

### 3.1 Value

A value is `vendor:product`: the vendor and product components of a CPE 2.3 name, separated by an unescaped colon, for example `nodejs:node.js`, `php:php`, `f5:nginx_open_source`, `microsoft:.net`.

- Written as NVD writes them in `cpe_normalized`: a character other than a letter, digit, `.`, `-` or `_` is escaped with a backslash (`notepad\+\+`, `1und1:1\&1_online_storage`). A backslash before `.`, `-` or `_` is dropped, because NVD writes those bare.
- Compared in lower case. A value in any case is accepted and lower-cased at compile time; the stored rule keeps what the caller sent.
- Each component must be a literal: not empty, not `*` or `-`, containing no unescaped `*` or `?`, and not ending in an unescaped backslash, which would escape the `:` that ends the compiled prefix.
- Printable ASCII only (`0x21` to `0x7e`), checked before lower-casing, so a character such as KELVIN SIGN cannot lower-case into an ASCII letter.
- At most 255 characters.

The checks are the version check endpoint's CPE rules (`internal/check/input.go` `parseCPE`: the printable-ASCII check, `splitCPE`, `dropRedundantEscapes`, `literalCPEValue`, `escapedAsCPERequires`), exported from `internal/check` (section 3.4). The rule adds refusals the check does not make: an unescaped `*` or `?` inside a vendor or product, which the check accepts, and a trailing unescaped backslash, which in a full CPE escapes the next colon, so the check refuses that CPE for its component count (`splitCPE`). Every product a rule accepts, the check accepts too; the parser's tests run each refusal through both.

The field is named `affected.cpe_product`, as the requirement writes it, because its value is a CPE identity even when the match comes from a CNA record.

### 3.2 Operators

`eq` and `in`. Two limits keep a rule's statement bounded:

- **At most 50 `affected.cpe_product` values per rule**, across all its product conditions (an `eq` counts as one). Each product value becomes its own `OR` terms and bind parameters (38 for `nodejs:node.js`: 6 prefix ranges of 3 and 5 CNA names of 4), because the index needs them as separate predicates (section 5.1); 50 values make at most a few thousand parameters.
- **At most 100 conditions per rule**, of any field. Every condition adds parameters, so without a bound on conditions a rule could still pass PostgreSQL's 65,535-parameter limit inside the 1 MiB request limit, fail on every evaluation, and hold the batch cursor for all rules (pitfall DB-12). Today no limit exists. 100 is a judgment, not a measurement: there are no production rules to count it against.

**Every list is bound as one array parameter**, `= ANY(?)` or `<> ALL(?)` with `pq.Array`, including the existing `in` and `not_in` of `cve_id`, `severity` and the other set fields. Today `setSQL` passes `sq.Eq{expr: vals}`, which squirrel expands to `IN (?, ?, …)`, one placeholder per value, so a single `cve_id in [...]` condition can pass 65,535 parameters inside 1 MiB on its own; that changes in this work. Package names and ecosystem values therefore cost one parameter per list and do not count towards the 50.

With both limits and array binding, a rule's worst case without candidate IDs is about 50 product values of about 40 parameters each plus 100 conditions of at most 4 each, under 2,500 parameters. The candidate-ID arrays the evaluator adds are counted in section 5.2.

The value carries no CPE part (`a`, `o`, `h`), and the field matches all three. The requirement's example has no part. Matching every part can only add matches for the 589 pairs that NVD files under more than one part, which fails towards alerting.

`neq` and `not_in` are refused: "no source names this product" is a noise filter, a different need from the alerting use cases, and with name aliasing across two sources its meaning would need its own design. Text operators are refused: a substring of a CPE name has no index and no stable meaning across the two sources. Either can be added later without changing stored rules.

Back-out: once this ships, stored rules and saved searches can hold `affected.cpe_product` and `affected.package` `eq`/`in`. If the code is reverted, `Compile` refuses the unknown field or operator, and the evaluator sets each such rule to `status=error` on its next evaluation (`failUncompilableRule`); a saved search holding one fails when it runs. Re-enabling a rule after a fix runs a new activation scan. The rules affected can be listed with `SELECT id FROM alert_rules WHERE conditions::text LIKE '%affected.cpe_product%' OR conditions::text ~ '"affected.package"[^}]*"operator": *"(eq|in)"'`.

### 3.3 Sources

A CVE matches a product when either source names it:

1. **NVD:** a `cve_cpe_matches` row with `vulnerable = true` whose `cpe_normalized` starts with `cpe:2.3:<part>:<vendor>:<product>:` for any part, for any of the product's CPE spellings (section 3.4).
2. **CNA:** a `cve_cna_affected` row whose vendor and product, in lower case, equal one of the product's CNA names, or start with a prefix name, and are not one of the product's other products (section 3.4). Every stored copy is read: the MITRE record's and NVD's relay of it.

A CNA row matches whatever its versions' statuses say, including an entry whose every version is `unaffected`; the version check (`internal/check/cna.go` `readEntry`) reads such an entry as no statement. This is decided in section 15.2 ("CNA entries that list every version as unaffected"), for these reasons:

- A rule with no version condition asks whether the CNA names the product. Status belongs with version conditions (requirement MATCH-3), which will read `versions` anyway.
- Filtering on status would make a match depend on the `versions` JSON, which neither option of section 7 tracks, so a CNA changing `unaffected` to `affected` would be another unevaluated change.
- It is not inconsistent with filtering NVD rows on `vulnerable`: `vulnerable = false` marks a platform or configuration CPE ("runs on"), not a statement that the product is unaffected.
- Cost: an alert for a CVE whose CNA lists the product only to say it is not affected. On the kept ingest 3,149 entries on 1,648 CVEs list versions that are all `unaffected` with no `affected` default; none is under the six products the name table maps.

Not read:

- `cve_affected_cpes`. It holds every CPE string any source names: NVD's criteria, including platform CPEs (`vulnerable = false`), the CPEs a CNA lists in its own record (`affected[].cpes`, `internal/feed/mitre/adapter.go`), Red Hat's CPEs in CPE 2.2 form and MSRC product names. Reading it roughly doubles the matches for operating systems (section 2). The CNA-supplied CPEs would be a day-one source: 5,162 CVEs have a CPE 2.3 row there that is not one of NVD's and no NVD match. But the table records no source, so they cannot be read apart from NVD's platform CPEs without a schema change, and the CNA's vendor and product names already cover most such records. CPE watchlist items still read the table (section 9).
- The version check's nearby names (a CNA row under the product's vendor whose product contains a fragment, such as `F5` / `NGINX Plus` for `f5:nginx`). The check endpoint uses them only to refuse a clean answer. Matching them in a rule would alert for other products of the same vendor (section 15.2, "Nearby CNA names").
- CNA `package_key`. That is a package identity, not a product (section 14).

The union is deliberate: an alert that fires from either source fails towards telling the user. A CNA entry for a product still matches after NVD's analysis leaves the product out, and the reverse.

### 3.4 Product names, shared with the version check

`internal/check/names.go` holds the table that maps a CPE product to its CNA spellings (`NamesFor`) and the CNA products that a name would wrongly find (`otherProducts`), with the rule that the CPE's own vendor and product, with `_` read as a space and also kept, are always names. That table is section 4.5 of the version check design (`dev/plans/2026-11-08-version-check-endpoint-design.md`; CNA spellings of six products: Node.js, PHP, nginx, .NET, PostgreSQL and Python).

The rule field uses the same table, so a rule and a check of one product read the same CNA rows. The rule compiler (`internal/alert/dsl`) imports `internal/check`, which imports only `internal/ecosystem` and `internal/version` (`go list -deps ./internal/check`), so no cycle arises and no code moves except:

- `internal/check` exports what the compiler needs: the name lookup (`NamesFor`, `CNAName`, the other-product list and rule behind `isOtherProduct`), `ProductRef`, a value parser holding section 3.1's checks, and the key builders `CPEKeyFor` and `cnaNameKey` with `cutRunes`, `nextPrefix` and the limits `CPEKeyRunes` and `cnaNameRunes`;
- the index-expression helpers `cpeIndexExpr` and `cnaNameIndexExpr` move from `internal/store/check.go` to `internal/check`, exported, and `internal/store` calls them there. The compiler cannot import `internal/store`, which imports `internal/alert/dsl`, and an expression that drifts from `cve_cpe_matches_check_idx` or `cve_cna_affected_check_idx` falls back to a sequential scan without an error.

Two rows are added to the Node row's names: `node.js` / `node.js` and `the node.js project` / `node.js` (section 2). They change no match today: all 19 stored rows are on CVEs NVD has analysed under `nodejs:node.js`. A check sees a table edit on its next request.

A rule does not: an edit to the table changes which stored CVEs a product rule matches, and nothing evaluates those CVEs until each next changes materially, so a newly matched CVE does not alert and an unmatched one keeps an open event. Pitfall NOTIFY-2 rejects leaving such a blind zone documented and unfixed. No blind zone exists at ship time, so this work builds the guard, not the remedy:

- A unit test pins a digest of the whole table: every row's CPE spellings, CNA names and nearby-name fragment, and `otherProducts`. Any edit fails the test until its author updates the digest. The failure message points to this section.
- The step an edit must ship with: the database stores one record per table row and per other-product entry, keyed by the entry's first CPE spelling and holding the entry's digest, CPE spellings and CNA vendors. On worker start, the worker compares those records with the table in code. Every added, changed or removed entry is a changed entry, and a removed entry's spellings and vendors come from its stored record. With no stored records, which is the first run after the step is built, every entry counts as changed. The worker evaluates every active rule that has an `affected.cpe_product` condition over the CVEs with a CNA row under any vendor of a changed entry, or a vulnerable CPE match row under any of its CPE spellings (adding a spelling makes a rule on one spelling read rows under the other), then stores the new records. `date_modified_canonical` does not move, because it must keep meaning "materially changed" for API polling and digests (section 7). The first edit that changes a match builds this step.
- Delivery in that evaluation is decided when the step is built (section 15.2, "Notifications after a name-table edit"). Delivering for every historical CVE that newly matches is the burst that pitfall NOTIFY-1 suppresses for activation scans; recording every match silently would hide a recent CVE that the old table missed. Recommended: deliver for CVEs published in the last 30 days, and record older new matches with delivery suppressed, as activation does. Resolutions follow the existing rule: one notifies only if a delivered event resolves.
- The test only proves the digest was touched, not that the step was built or run; it is a prompt to the author and reviewer, not a proof.

### 3.5 Alert behaviour over a CVE's life

For a Node CVE such as CVE-2026-123866:

1. The CNA record arrives (MITRE, or NVD's relay before analysis). The CVE is new, so its first `material_hash` runs realtime evaluation, and the rule fires. If another feed (OSV, GHSA, KEV) delivered the CVE first without a CNA entry, the CNA rows arrive on a later merge, which is step 4's case.
2. NVD analyses the CVE and adds CPEs. `cve_affected_cpes` is a `material_hash` input, so the hash changes and the rule fires a second time for the same CVE. This is the existing meaning of a material change (PLAN.md §5.3, affected CPE set). It means two notifications per product CVE that NVD analyses later.
3. NVD flips a CPE between vulnerable and not vulnerable with the same criteria string. The hash does not change, so on its own nothing would re-check the CVE. Section 7's re-check signal covers it: the flip changes `match_inputs_hash`, so the rules are evaluated again, and a rule that now matches fires once.
4. The CNA changes its product names, with nothing else material. The same signal covers it (section 7).

### 3.6 Alternatives not chosen

- **Separate `affected.vendor` and `affected.product` fields**, correlated like the package fields. A vendor alone is not a usable key: the CNA and NVD spell vendors differently (`php group` against `php`, `the node.js project` against `nodejs`), so a vendor value would match one source and miss the other, and only the pair can go through the name table.
- **Extend the CPE watchlist item to read CNA names**, with no rule field. The requirement asks for a rule that works without a watchlist, and changing the CPE item would change what existing items match, including their platform CPEs (section 9).

## 4. Package conditions: exact match and correlation

### 4.1 Exact match

`affected.package` gains `eq` and `in`. A value matches a stored row when the names are equal after folding for the row's ecosystem (`ecosystem.FoldPackageName`, the folding merge and the watchlist package match use). So `Foo_Bar` matches PyPI `foo-bar` and npm `foo_bar`, not npm `foo-bar`. "Exact" therefore means equal after the ecosystem's own folding, never a comparison of the stored spelling (confirmed by Sam with the requirements, section 15.1). An empty or whitespace-only value is refused. Section 5.1 gives the SQL.

Ecosystems are compared exactly, where today's compiler and `watchlistExpr` lower-case them. Rule values must be canonical OSV names already (`ecosystem.Valid`), and stored values are canonical since the ecosystem vocabulary was unified at ingest, so the two readings agree on stored data; the exact form lets `cve_affected_packages_check_idx` serve `ecosystem = ANY`, which `lower(ecosystem)` cannot. It departs from PLAN.md §10.2, which requires case-insensitive `eq`; section 11 adds a clarifying line to §10.2 (section 15.2, "Ecosystems compared exactly").

### 4.2 Correlation

Under `logic: and`, each `affected.package` condition must hold on one `cve_affected_packages` row together with every `affected.ecosystem` condition that uses `eq` or `in`. `{affected.ecosystem eq Debian, affected.package eq openssl}` means "a Debian row (any release) for openssl".

- Package conditions are not correlated with each other. `{affected.ecosystem eq npm, affected.package eq a, affected.package eq b}` means "an npm row for a, and an npm row for b", so a rule can still ask for a CVE that affects both. This is the narrower of two readings; section 15.2 ("Package conditions stay independent") records the other.
- `affected.ecosystem` with `neq` or `not_in` stays a condition on the whole CVE: "the CVE has no row in this ecosystem". Read per row it would mean "some row in another ecosystem", which says nothing useful.
- A rule with ecosystem conditions and no package condition matches as today: each ecosystem condition on its own.
- Under `logic: or`, each condition is matched on its own, as today. "Npm, or a package named lodash" has no single row to correlate.
- `affected.cpe_product` is not correlated with package conditions. It reads different tables, and a rule that names both a product and a package asks for a CVE that has both.

As compile rules, for an `and` rule:

1. Each package condition becomes one set (section 5.1) holding its own predicate and the predicate of every `eq` or `in` ecosystem condition in the rule.
2. When the rule has a package condition, its `eq` and `in` ecosystem conditions are not emitted again on their own: every package set already requires a row in those ecosystems.
3. When the rule has no package condition, each `eq` or `in` ecosystem condition becomes its own set, which matches as today.
4. `neq` and `not_in` ecosystem conditions are always emitted on their own, as `NOT EXISTS`.

Under rule 1, two `eq` or `in` ecosystem conditions beside a package condition must both hold on the package's row, so `{ecosystem eq npm, ecosystem eq PyPI, package contains x}`, which today matches a CVE with an npm row, a PyPI row and an `x` row, matches nothing. The validator refuses that shape at save (section 8).

### 4.3 Existing rules change meaning

An existing `and` rule with an ecosystem and a package condition matches fewer CVEs once this ships. When a CVE that no longer matches is next evaluated (realtime on its next hash change, or a batch or EPSS run that includes it), its open event resolves and a resolution notification is sent ("no longer matches the rule's conditions"). Until then, events opened under the old reading stay open. Section 7's re-check signal treats a stored NULL `match_inputs_hash` as a change, so each CVE with an event is re-evaluated on its first merge after this ships, and most of these events resolve then. PLAN.md §10.5 says a changed meaning bumps `dsl_version` and keeps the old compiler. This design does not: the project has no users, and keeping the uncorrelated reading would keep the wrong answer. Without a version, reverting the correlation is a code revert: rules widen again from each CVE's next evaluation, and a CVE whose event was resolved by this change reopens at the same hash and notifies (PLAN.md §10.4). Section 15.2 ("No `dsl_version` bump") records the decision.

## 5. Query shape

### 5.1 The CVE-set form

Each product condition, and each package condition with its correlated ecosystem conditions, compiles to a membership test on a set of CVE IDs. For a product condition (one set per condition, whatever the length of its `in` list):

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
      AND (
            ((<name term a1> OR <name term a2> ...) AND NOT (<other products of value a>))
         OR ((<name term b1> ...) AND NOT (<other products of value b>))
         OR ...)                               -- one group per value of the in list
)
```

A name term is `(left(lower(a.vendor), 256) COLLATE "C" = $v AND left(lower(a.product), 256) COLLATE "C" = $p AND lower(a.vendor) = $fullv AND lower(a.product) = $fullp)`, or for a prefix name a range on the cut product with the same full-vendor recheck. Each value's other products exclude rows only within that value's group. One shared exclusion would be wrong: in `in [microsoft:.net, microsoft:.net_framework]`, the CNA row `Microsoft` / `.NET Framework` is an other product of the first value and a name of the second, and must match through the second.

A row is one of a value's other products when its lower-cased vendor equals the other product's vendor, and its lower-cased product equals the other product's name or, for a prefix, starts with it and is followed by nothing or by a character that is not an ASCII letter or digit. In SQL the following character is tested with `!~ '^[a-z0-9]'` on the lower-cased product, and `isOtherProduct` changes from `unicode.IsLetter`/`IsDigit` to the same ASCII test, so the boundary test itself does not depend on the database's character type. The lower-casing before it still does, as the next paragraph says. Every name and other product in the table is ASCII; the only change in behaviour is that a prefix followed by a non-ASCII letter now counts as a word boundary. On the kept ingest no Microsoft product name has a non-ASCII character after either `.NET Framework` prefix (0 rows), so no stored row changes.

PostgreSQL's `lower()` follows the database's character type, while names in the table and rule values are ASCII and are lower-cased in Go. Only stored non-ASCII vendor or product text can therefore compare differently between deployments: such a name, whose non-ASCII letter (KELVIN SIGN, for example) lower-cases to an ASCII letter in one locale, matches a table name, or reads as a letter after an other-product prefix, in that locale and not in another.

The SQL for product sets, name terms and other products is built in `internal/alert/dsl` by an exported function, from the names, keys and index expressions `internal/check` exports (section 3.4).

For a package condition (compile rules in section 4.2):

```sql
cves.cve_id IN (
    SELECT cap.cve_id FROM cve_affected_packages cap
    WHERE cap.cve_id = ANY($candidates)        -- only when the caller has candidate IDs
      AND (cap.ecosystem = ANY($ecos1) [OR cap.ecosystem LIKE ANY($releases1)])   -- one line per eq/in ecosystem condition
      AND <package predicate>
)
```

`$ecosN` holds an ecosystem condition's values. The bracketed release arm is emitted only when the condition holds a value whose base ecosystem takes a release suffix (`Debian`, `Ubuntu`, `Packagist` and the others in `internal/ecosystem`'s `takesSuffix`, which gains an exported accessor), bare or already suffixed. `$releasesN` then holds those values, LIKE-escaped, followed by `:%`, so `Debian` matches `Debian:13` and `Ubuntu:22.04` matches `Ubuntu:22.04:LTS`, as today, where `affectedEcosystemSQL` appends `:%` to every value. A line with no release arm, such as `npm` alone, leaves `ecosystem = ANY` for the index to serve. Every list is one array parameter, whatever its length.

The package predicate:

| Operator | Predicate |
|---|---|
| `eq` or `in` | `<folded name> = ANY($names)`, where `<folded name>` is `ecosystem.FoldedNameSQL("cap.ecosystem", "cap.package_name")`, the expression of `cve_affected_packages_check_idx`, and `$names` holds the values folded in Go for the ecosystems the rule names. Folding differs only for PyPI. When the rule's ecosystem values include PyPI and another ecosystem, or the rule names no ecosystem, the predicate has two arms: `(cap.ecosystem = 'PyPI' AND <folded name> = ANY($pypiNames)) OR (cap.ecosystem <> 'PyPI' AND <folded name> = ANY($names))`. Measured: `npm` with `in [lodash, express, axios]` reads the index on both columns (4.7 ms); with no ecosystem, PostgreSQL 18 reads the index by skip scan on the ecosystem column (217 ms cold, 16 ms warm, section 5.3). |
| `contains`, `starts_with`, `ends_with` | `lower(cap.package_name) ILIKE $pattern`, escaped as today. |

`neq` and `not_in` on `affected.ecosystem` keep today's correlated `NOT EXISTS`, not `NOT IN`: on the kept ingest a dry-run of `ecosystem neq npm` with severity critical ran 243 ms as `NOT EXISTS` and hit a 60 s statement timeout as `cves.cve_id NOT IN (...)`. Ranges, prefixes, names and folded package names are built in Go from `internal/check` and `internal/ecosystem` and passed as parameters, never concatenated.

Two details are load-bearing, from the measurements in section 5.3:

- **Candidate IDs inside the set.** Realtime, batch, EPSS and activation pass candidate IDs. Without them inside each branch, the set for a large product is built in full for each evaluation (283 ms for `linux:linux_kernel` against one CVE); with them, 0.28 ms.
- **Ranges and names as `OR`-ed predicates, not a join to `unnest()` arrays.** With the join, the planner chose a sequential scan of `cve_cpe_matches` (7.7 to 13.9 s under `and`, over 60 s under `or`); with `OR`-ed predicates it uses a bitmap `OR` over `cve_cpe_matches_check_idx` (2.6 ms for Node).

This also changes how today's `affected.ecosystem` (`eq`, `in`) and `affected.package` compile, because correlation needs one set per package condition. The correlated case got faster in the one comparison measured: `npm` with `contains lodash` on one row took 0.88 s as a set, against 4.7 s for today's `contains lodash` alone. A substring package condition with no ecosystem, in the set form, is not measured (section 13).

### 5.2 Compiler and evaluator contract

`CompiledRule.SQL` becomes a method, `CompiledRule.Where(candidateIDs []string) sq.Sqlizer`, because the set's SQL depends on the caller's candidate IDs. A nil or empty slice means no candidate filter, as `queryCandidates` already treats an empty list. Callers:

| Caller | Candidate IDs |
|---|---|
| `alert.Evaluator.queryCandidates` (realtime, batch, EPSS, activation) | its own list |
| `alert.Evaluator.DryRun`, `store.ExecuteDSLQuery` (saved searches, AI search) | none |

`queryCandidates` keeps appending `cves.cve_id = ANY(?)` itself; each set repeats the same list. Squirrel numbers every placeholder separately, so the array is sent once per copy: two copies per product condition (one per branch), one per package condition, and one outer. The worst rule within the limits has 50 one-value product conditions (100 copies) and 50 package conditions (50 copies), about 150 copies; a batch chunk is 5,000 IDs, so that rule sends about 750,000 IDs per statement. Section 13 measures this case; a common rule of a few conditions carries a handful of copies.

The rule cache keeps caching `CompiledRule`. The watchlist pre-filter (`watchlistExpr`) is unchanged.

Decided for the compiler:

- `affected.cpe_product` gets its own field kind, `kindProduct`, so `ExportFieldDescriptions` gives it `TypeDesc` `"CPE vendor:product"` (section 10).
- `Compile` re-applies the value parser and both limits to every stored rule, as `Validate` does at save. A stored rule that fails them compiles to an error, and the evaluator sets it to `status=error` (`failUncompilableRule`), failing closed as PLAN.md §10.5 requires.
- Values are counted towards the 50-product limit after normalisation (lower case, redundant escapes dropped) and de-duplication, so `NodeJS:Node.js` and `nodejs:node\.js` count once.
- Create and PATCH run the same validation and return the same errors (section 12 tests both, testing-pitfalls §4).

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
| Dry-run, `Debian` and `openssl` correlated (value folded per row) | not applicable | 0.90 s |
| Dry-run, `npm` and `eq lodash`, single values compared with the index expression | not applicable | 0.52 ms |
| Dry-run, `affected.package eq openssl`, no ecosystem (value folded per row, a form not built) | not applicable | 10.5 s |
| Dry-run, `affected.package eq openssl`, no ecosystem, pre-folded two-arm form of section 5.1 | not applicable | 217 ms cold, 16 ms warm (index skip scan) |
| Dry-run, `npm` and `in [lodash, express, axios]`, one-arm array form | not applicable | 4.7 ms |
| Dry-run, `affected.ecosystem neq npm` with severity critical | 243 ms (`NOT EXISTS`) | over 60 s (`NOT IN`; not used, section 5.1) |
| Saved-search shape (`ORDER BY date_modified_canonical DESC, cve_id DESC LIMIT 51`), `linux:linux_kernel` | not measured | 357 ms |

Realtime evaluates every active rule against each CVE whose hash changed, so its cost per rule is what matters at ingest; under 1 ms per product rule adds little to a merge that takes milliseconds. A package name with no ecosystem was the one slow case, at 10.5 s with the value folded per row. The form section 5.1 builds compares against values folded in Go, and PostgreSQL 18 then reads `cve_affected_packages_check_idx` by skip scan over its ecosystem column (1,001 index searches): 217 ms cold. PostgreSQL 15 to 17 have no skip scan, so there the shape may still scan the table; section 13 measures it. The validator's warning reaches only the validate endpoint: create, PATCH, saved searches and AI search act on errors alone (section 8), so the warning cannot be what keeps the shape cheap. Three remedies were weighed:

- an index on the folded name alone, which costs a write on each of 7.5 million package rows at every merge, and which PostgreSQL 18's skip scan makes unnecessary;
- expanding a missing ecosystem to the ecosystems present, which needs a query for the stored ecosystem list (hundreds of release strings) before every evaluation;
- refusing `affected.package` `eq` or `in` in an `and` rule with no `eq` or `in` ecosystem condition. The operators are new, so no stored rule breaks, and under `and` the fix is to add the ecosystem. Under `or` nothing correlates, so refusing there would remove `eq` from every `or` rule. Section 15.2 ("Exact package match with no ecosystem") records the decision: allowed.

The `or` rows above ran with hashed SubPlans. A SubPlan is hashed only when its estimated size fits in `hash_mem` (default `work_mem` 4 MB × `hash_mem_multiplier` 2; the project sets neither), so a wide `or` product rule may fall back to a SubPlan rescanned for each CVE row; section 13 measures it.

Appendix A holds the measured statements, so the implementation plan can repeat these rows on the kept ingest once the code exists (section 13). The batch rows above compare different products across the two forms, so the batch cost of the set form against today's form is not known; the set form was chosen on the dry-run rows and the equal realtime rows.

## 6. Indexes

The CVE-set form adds no index; it uses indexes that exist. The re-check signal of section 7 adds one, `cves_date_match_inputs_changed_idx` (section 7.2).

| Index | Used by |
|---|---|
| `cve_cpe_matches_cve_id_idx`, `cve_cna_affected_cve_id_idx`, `cve_affected_packages_cve_id_idx` | Candidate IDs inside the set (realtime, batch, EPSS, activation) |
| `cve_cpe_matches_check_idx` on `left(cpe_normalized, 512) COLLATE "C"` | CPE prefix ranges, whole corpus |
| `cve_cna_affected_check_idx` on `left(lower(vendor), 256)`, `left(lower(product), 256)`, `COLLATE "C"` | CNA names, whole corpus |
| `cve_affected_packages_check_idx` on `(ecosystem, folded name)` | Exact package match with an ecosystem |

So rule matching adds no write cost to merge. The re-check signal adds one hash computation per merge, and an index write only when a CVE's match inputs change.

## 7. Changes that do not move the material hash

A rule now matches on two things that are not `material_hash` inputs: the product names in CNA rows, and NVD's `vulnerable` flag on CPE match rows (section 3.5, steps 3 and 4). Today, a change to them alone runs no realtime evaluation and does not move `date_modified_canonical`, which the batch path follows. So a CNA that corrects `n/a` to `Node.js`, with nothing else material, never triggers a Node rule. Pitfall NOTIFY-2 rejects leaving that open.

**Decided by Sam (2026-11-13): a separate re-check signal, not a material-hash change.** Sam's reason: alert rules must not fire again on informational churn, and putting these inputs into `material_hash` would do exactly that (section 15.1).

### 7.1 The signal

- **New columns on `cves`:** `match_inputs_hash text` and `date_match_inputs_changed timestamptz`, both nullable. `match_inputs_hash` is `sha256(jcs(...))`, computed the same way as `material_hash` (RFC 8785 canonical JSON), over two sorted, distinct lists:
  - the CNA vendor and product pairs, lower-cased as the match compares them (section 3.3), with a missing value as an empty string;
  - the `part:vendor:product` keys of the CVE's `vulnerable = true` CPE match rows.
- **In merge** (`internal/merge/pipeline.go`), in the same transaction and under the same per-CVE lock as `material_hash`:
  - compute `match_inputs_hash` from the resolved CNA rows and CPE matches;
  - when it differs from the stored value, write the new value and set `date_match_inputs_changed` to the clock value that would be used for `date_modified_canonical`.
  - A stored NULL counts as different. On the first merge after this ships, each redelivered CVE is therefore re-checked once. That costs evaluation work but sends no duplicate alerts: an alert that already exists at the same `material_hash` is not inserted again. It also covers a rule created after the deploy, whose activation scan read data that changes before the CVE's first new merge.
- **Realtime** (`internal/ingest/handler.go`): the handler already reads `material_hash` before and after each merge. It reads `match_inputs_hash` the same way, and runs `EvaluateRealtime` when either value changed.
- **Batch** (`internal/alert/evaluator.go`): the candidate scan selects CVEs whose `date_modified_canonical` **or** `date_match_inputs_changed` is after the cursor, minus the same 2-minute rescan window. This catches a CVE whose realtime evaluation failed. The two conditions are written as a `UNION` of two keyset scans, one per column, so each can use its own index.
- **EPSS path:** unchanged. EPSS-only rules cannot hold product conditions.
- **Dedupe:** unchanged. `alert_events` stays unique on `(org_id, rule_id, cve_id, material_hash)`.
  - A rule that newly matches inserts an event at the current hash and notifies once.
  - A rule whose match ends resolves its event, as today.
  - A rule that matches again at the same hash reopens and notifies (PLAN.md §10.4).
  - Rules whose match did not change see no new event, so they do not fire again.
- **API:** neither column is exposed. `date_modified_canonical` keeps meaning "materially changed" for API polling and digests.
- **Version conditions** (requirement MATCH-3) extend `match_inputs_hash` with CNA version entries and NVD ranges. Changing what the hash covers moves every stored value once, which re-checks each CVE once on its next merge, again with no duplicate alerts.

### 7.2 Migration and indexes

One migration pair adds the two columns. The up file creates `cves_date_match_inputs_changed_idx` on `(date_match_inputs_changed)` `CONCURRENTLY`, partial `WHERE date_match_inputs_changed IS NOT NULL`, with `-- migrate:no-transaction` as its first line (project conventions). The design is reviewed with the `schema-review` skill and written with the `migration` skill before code. Adding a nullable column with no default rewrites no rows.

### 7.3 Rejected: putting the inputs into `material_hash`

- How it would work: the CNA product pairs and vulnerable CPE keys join `MaterialFields`. This is one mechanism instead of two.
- Why rejected: every change to those inputs would fire every rule matching the CVE again, including rules that do not look at products, such as "severity critical". That is the informational churn alerting must avoid; description edits are kept out of the hash for the same reason. MITRE and NVD each keep a copy of a CNA record, so one CNA edit could fire twice.
- One-time cost it would also have had: 405,809 CVEs with CNA rows, or every NVD-analysed CVE once the vulnerable flag is included, would show as materially changed and re-fire their rules as feeds redeliver them.
- Further cost: version conditions would need another corpus-wide hash move.

## 8. Validation and messages

Errors stop a save. Messages follow the existing `ValidationError` list (`internal/alert/dsl/validator.go`), one entry per problem, with the condition index. Today warnings reach a caller only through `POST .../alert-rules/validate`: create and PATCH (`internal/api/alert_rules.go`) act on blocking errors alone, and saved searches and AI search drop warnings. So a warning cannot be relied on to stop a rule shape. Under section 4.2, an `and` rule with a package condition and several `eq`/`in` ecosystem conditions matches only a row whose ecosystem satisfies all of them. That is satisfiable when the conditions share an ecosystem (`in [npm, PyPI]` with `eq npm`; `Debian` with `Debian:13`), and can never match when they share none. The never-matching case is refused at save (section 15.2, "Never-matching ecosystem conditions"), because such a rule is a mistake whoever wrote it. The case is defined as an empty intersection: each ecosystem condition's values cover themselves and, for a value whose base takes a release suffix, every release under it, and no ecosystem is covered by all of the conditions.

| Case | Severity | Message |
|---|---|---|
| `affected.cpe_product` value without exactly one unescaped colon, or an empty part | error | `value must be "vendor:product", the vendor and product of a CPE 2.3 name, for example "nodejs:node.js"` |
| Part is `*` or `-`, or holds an unescaped `*` or `?` | error | `vendor and product must be literal names, not "*", "-" or a pattern with "*" or "?"` |
| Part ends in an unescaped backslash | error | `vendor and product must not end in an unescaped backslash` |
| Unescaped character that CPE 2.3 requires escaped | error | `character "+" must be escaped with a backslash, as NVD writes CPE names (for example "notepad\+\+")`, naming the first such character |
| Over 255 characters | error | `value must not exceed 255 characters` |
| `in` with no values, on `affected.cpe_product` or `affected.package` (existing fields keep today's behaviour) | error | `value must list at least one item` |
| More than 50 values across the rule's `affected.cpe_product` conditions | error, rule-level (index -1) | `a rule may name at most 50 products in total` |
| More than 100 conditions | error, rule-level (index -1) | `a rule may hold at most 100 conditions` |
| An `and` rule with a package condition and `eq`/`in` ecosystem conditions that no ecosystem satisfies together (the empty intersection defined above) | error, rule-level | `every ecosystem condition must hold on the same package row, and no ecosystem satisfies all of them, so this rule can never match; use one "in" condition if any of them is enough` |
| An operator other than `eq` or `in` on `affected.cpe_product` | error | the existing `operator %q is not valid for field %q` |
| A product with no row in the name table | warning | `no other CNA spelling is known for "x:y"; before NVD analyses a CVE, it matches only if the CNA record names vendor "x" and product "y"` (with `_` shown as a space where the own names do) |
| `affected.package` `eq` or `in` with an empty or whitespace-only value | error | `value must not be empty` |
| `affected.package` `eq` or `in` in an `or` rule, or in an `and` rule that has no `affected.ecosystem` condition with `eq` or `in` | warning | `without an ecosystem condition in an "and" rule, this match cannot narrow by ecosystem first and may be slow on PostgreSQL versions before 18` |

`affected.cpe_product` joins `selectiveFields`, so a regex rule with a product condition is allowed without a watchlist. The validator needs no database; the warning about unmapped products comes from the table in code.

## 9. Watchlists

**Recommendation: no new watchlist item type in this work.** `affected.cpe_product in [...]` lists a lab's products in one rule, which is what the requirement's text asks for. A product item type (`item_type = 'product'`, a `vendor:product` column, matched by the same set SQL as the rule field) would let one list feed several rules and digests, which PLAN.md §9.1 anticipates ("vendors/products, optional convenience"). It needs a migration, API and SPA changes to the watchlist views. Section 15.2 ("No watchlist product item in this work") records the decision.

Interaction with the existing CPE item, which stays as it is: a CPE item matches `cve_affected_cpes` by prefix, including NVD platform CPEs and with no CNA names, while the rule field reads NVD's vulnerable rows and CNA names. A rule bound to a CPE-item watchlist and using the field gets the intersection of the two. The field's description in PLAN.md says how the two differ, so a user does not expect them to agree.

## 10. Frontend, AI search and API description

- **SPA:** no change. There is no rule editor, and the CVE detail page's affected section is not part of this work.
- **AI search:** the prompt lists every registered field from `ExportFieldDescriptions`, so the new field and operators appear without code, and `PromptVersion` changes. Three lines are added to the prompt's notes: `affected.cpe_product` takes `vendor:product` from a CPE name, such as `nodejs:node.js`; in an `and` rule, `affected.ecosystem` and `affected.package` describe the same package, so name the package's ecosystem with it; and `affected.package` `eq` matches a whole package name. `FieldDescription.TypeDesc` for the field is `"CPE vendor:product"`.
- **OpenAPI:** no change; rule conditions are JSON the spec does not enumerate. `schema.d.ts` is not regenerated.

## 11. PLAN.md changes

- §10.1: add `affected.cpe_product` (CPE `vendor:product`; NVD vulnerable CPE rows and CNA names) and note that `affected.ecosystem` and `affected.package` are matched on one row under `and`.
- §10.2: `affected.package` takes `eq` and `in`, compared after package-name folding.
- §10.2's list of selective constraints for regex rules: add `affected.cpe_product`.
- §10.2: the rule limits (50 product values, 100 conditions), the empty-`in` error on the new operators, and lists bound as one array parameter.
- §10.2's case-insensitive `eq`: ecosystems are compared exactly, because rule values and stored values are both canonical names (section 15.2).
- §10.5: record that the correlation change ships without a `dsl_version` bump (section 15.2).
- §5.3: CNA product names and NVD's vulnerable flags are match inputs outside `material_hash`; §10.3: the re-check signal of section 7 (`match_inputs_hash`, `date_match_inputs_changed`) as a trigger for realtime evaluation and a second batch cursor condition; Appendix A: the two new `cves` columns and index.
- Appendix A's `cve_cpe_matches` and `cve_cna_affected` entries: alert rules read them.

## 12. Tests

TDD per the project rules. Integration tests use testcontainers through `testutil.NewTestDB`.

**Unit (`internal/alert/dsl`, `internal/check`):**

- Value parsing: valid values from section 2's escaped rows (`1und1:1\&1_online_storage`), `\.` dropped, uppercase lower-cased, KELVIN SIGN refused, `nodejs:node.js\` refused, each error row of section 8, 255 and 256 characters; a rule with 50 product values over several conditions passes and one with 51 fails; a rule with 100 conditions passes and one with 101 fails.
- Each refusal the rule adds to the check's parser (section 3.1) is also refused by the check in a full CPE.
- `affected.package eq " "` is refused.
- The unmapped-product warning appears for `example:widget` and not for `nodejs:node.js`; the never-matching ecosystems error appears for `{ecosystem eq npm, ecosystem eq PyPI, package contains x}` and not for `{ecosystem in [npm, PyPI], ecosystem eq npm, package eq x}` or `{ecosystem eq Debian, ecosystem eq Debian:13, package eq openssl}`.
- `internal/check` keeps its existing name tests, plus the two new Node names, and `isOtherProduct` treats a non-ASCII letter after a prefix as a boundary.
- The table digest test (section 3.4) fails when any row, CPE spelling, CNA name, fragment or other product changes, and its message names section 3.4's required step.
- Create and PATCH return the same validation errors for the same conditions (testing-pitfalls §4); a stored rule edited past a limit compiles to an error.

**Parity (integration, in `internal/alert`, which has a `TestMain`):** for every other-product entry, and for each entry's name followed by an ASCII letter, a digit, a space, nothing, and a non-ASCII letter (`é`), the SQL exclusion built by `internal/alert/dsl` and `check.IsOtherProduct` agree. Both sides use the ASCII test of section 5.1, so the result does not depend on the database's character type.

**Integration with `testutil.SeedCorpus`** (71 records). The golden NVD page holds CVE-2026-56847 (CNA `nodejs` / `node` and NVD `nodejs:node.js`), CVE-2026-111497 (CNA `Google` / `Brotli`, NVD lists Node) and CVE-2026-107832 (`Awaiting Analysis`, CNA `fastify` / `fastify` only, with a CVSS metric).

- A rule `{affected.cpe_product eq fastify:fastify, severity in [critical, high, medium, low]}` matches CVE-2026-107832 with no NVD row; this is the seeded form of the acceptance case. The CVE's only severity in the golden fixtures is CVSS 3.1 3.7 LOW (`internal/feed/nvd/testdata/golden/page-001.json`), and the test asserts it, so a fixture change fails loudly. The same rule without `low` does not match.
- Two product values in one condition: `in [microsoft:.net, microsoft:.net_framework]` matches a hand-built CNA row `Microsoft` / `.NET Framework` (the second value's own name), which `microsoft:.net` alone does not (section 5.1).
- `nodejs:node.js` matches CVE-2026-56847 and CVE-2026-111497; `google:brotli` matches CVE-2026-111497 from both sources.
- **Same answer on every path:** for a set of rules (each section 3 and 4 shape, `and` and `or`), the CVE IDs that `store.ExecuteDSLQuery` returns when paged to the end (no candidate IDs) equal the CVE IDs of the alert events an activation scan writes (1,000-ID candidate pages). Both are public seams; `DryRun` returns only a count and 10 samples, so it is checked on count alone. This is the guard on section 5.2's two forms of one rule.

**Integration with hand-built patches** (`feed.CanonicalPatch`, run through the merge pipeline):

- The acceptance case: a copy of CVE-2026-56847's CNA entry with no NVD configuration and severity `HIGH`, ingested so realtime runs; the rule fires. Then an NVD patch adds `nodejs:node.js`: the hash changes and the rule fires a second time (section 3.5).
- A CVE whose only Node CPE is `vulnerable: false` does not match.
- CNA `Node.js` / `Node.js` and `The Node.js Project` / `Node.js` match `nodejs:node.js`.
- `.NET 9.0 runtime` matches `microsoft:.net`; `.NET Framework 4.8` and `OpenAPI.NET` do not; `.NET FrameworkExtensions` does.
- A CNA vendor of 300 characters whose first 256 equal a table name does not match (the full-name recheck).
- A rejected CVE with a matching product does not match.
- Correlation: a CVE with npm `foo` and PyPI `lodash`. `{ecosystem eq npm, package eq lodash}` under `and` does not match; under `or` it does; `{ecosystem eq PyPI, package eq lodash}` matches.
- Folding: `package eq Foo_Bar` matches PyPI `foo-bar`, not npm `foo-bar`.
- `ecosystem eq Debian` with `package eq openssl` matches a `Debian:13` row; `ecosystem neq npm` with `package eq lodash` is a CVE-level `NOT EXISTS` and does not match a CVE that also has any npm row.
- Two package conditions: `{ecosystem eq npm, package eq a, package eq b}` matches a CVE with npm rows for a and for b, and not a CVE with only one of them.
- Re-check signal (section 7): a CNA product change alone, or a vulnerable flag flip, runs realtime evaluation without moving `material_hash` or `date_modified_canonical`; a new match fires once; an unrelated rule that already fired does not fire again; when realtime evaluation fails, the next batch run evaluates the CVE; a case-only difference between the MITRE and NVD copies does not change `match_inputs_hash`; a CVE whose stored value is NULL is re-checked once and sends no duplicate alert.
- Late-binding: after a CVE ID move, a product rule matches the new ID (the CNA and CPE match rows move with it).

## 13. Measure during implementation

On the kept complete ingest, with the built code:

- the section 5.3 rows for realtime (one CVE, `linux:linux_kernel`), batch (5,000 IDs), dry-run (Node, `linux:linux_kernel`) and the saved-search shape;
- the limit rule: 50 one-value `affected.cpe_product` conditions naming the 50 products with the most vulnerable CPE rows (the largest is `linux:linux_kernel`), plus 50 one-value `affected.package` conditions, measured under `or` and under `and` (under `and` it can match nothing and the planner may stop at the first empty set, so `or` gives the worst case and is the one the thresholds apply to), realtime against one CVE, dry-run, and **batch with a 5,000-ID chunk**, where the candidate array is sent about 150 times (section 5.2), including planning time;
- an `or` rule with 50 of those products in dry-run, checking that the set SubPlan stays hashed (section 5.3);
- the array form of section 5.1's package predicate: `npm` with an `in` of 50 names, `Debian` with `eq openssl`, and `eq` and `contains` with no ecosystem;
- the realtime, batch and dry-run rows again on PostgreSQL 15, including the dry-run of `affected.package eq openssl` with no ecosystem in the built form. Every test helper and compose file pins `postgres:18-alpine`, and PostgreSQL 18 adds planner features these plans use or may use (btree skip scan, `OR` lists turned into arrays), so the supported range 15 and later is unmeasured until this runs. If the no-ecosystem package dry-run takes over 5 s cold on PostgreSQL 15, the decision to allow that shape (section 15.2) is revisited;
- a full activation scan of the limit rule under `or`, so that it matches and the per-match statements run: it must finish well inside the 15 minutes after which `SweepZombieActivations` fails the job and sets the rule to `error` (about 2,600 pages of 1,000 IDs, so under about 340 ms a page, which must also cover `cveExists` and `InsertAlertEvent`, two statements per matched CVE).

Thresholds that go back to Sam before merge: a realtime row over 5 ms; a batch chunk over 3 s, well under the 14 s statement timeout, because a failed batch statement holds the cursor for every rule for up to 30 runs (`batchMaxHeldRuns`); a dry-run over 5 s, except a substring package condition with no ecosystem, which takes 4.7 s in today's form and goes back only if the set form is slower than that; an activation over 7 minutes. If the limit rule fails the batch threshold, the fallback is a lower limit on set-type conditions only (`affected.cpe_product`, `affected.package`, and `eq`/`in` ecosystem conditions in a rule with no package condition), which are the conditions that carry candidate-array copies; scalar conditions keep the limit of 100. A shared candidate CTE is not the fallback: a CTE referenced from several branches is materialised, and a join to it is the `unnest` shape section 5.1 measured as a sequential scan.

## 14. Not in scope

- Version conditions in rules (requirement MATCH-3).
- CNA `package_key` for `affected.package`. 3,905 CVEs have a CNA package key and no package row under that CVE, 573 of them with no GHSA or OSV source at all (measured on the kept ingest for Phase 4 of `dev/plans/2026-11-09-version-check-endpoint-plan.md`). A package rule could read them, but that changes what "package" means for a rule; a later change can add it.
- `neq` and `not_in` on `affected.cpe_product` (section 3.2).
- Showing CNA rows on the CVE detail page.

## 15. Sam's rulings and decisions taken

Agents will write the code from this document, so every choice is written down here. Section 15.1 records the two questions only Sam could answer, and his rulings. Section 15.2 records the choices the design made itself, because the evidence or the project's own rules settle them. Each entry gives the problem, the options and the reason, so Sam can overturn any of them.

### 15.1 Sam's rulings (2026-11-13)

Two questions needed Sam: one about his own requirement, and one architecture choice. Both are answered. No question for Sam remains open.

**The restated requirements are right.**

- The question: the requirement comes from Sam's private homelab integration document, which this public repository cannot quote, so section 1 restates it. Was the restatement faithful?
- It covered four points:
  - the product field;
  - correlating a rule's ecosystem with its package name;
  - "exact match" meaning the same name ignoring the differences each ecosystem itself ignores (lower case everywhere; `-`, `_` and `.` treated as one character for Python packages);
  - the acceptance test using a Node CVE named by its CNA instead of the Brotli CVE, which no CNA-based rule can match before NVD's analysis.
- Ruling: yes, to all four.

**Changes that do not move the material hash are caught by a separate re-check signal.**

- The question: rules now match on CNA product names and NVD's `vulnerable` flag, which are not in `material_hash`, so a change to them alone re-checks nothing.
- Options:
  - A: put them into `material_hash`. One mechanism, but every such change would fire every rule matching the CVE again, including rules unrelated to products, and 405,809 CVEs would re-fire once.
  - B: a separate signal that re-checks the CVE without changing the hash.
- Ruling: B. In Sam's words, "The excess rule firing on info churn is what we're trying to avoid." He also noted that no deployment has rules yet, so nothing on a live instance depends on the choice.
- Section 7 specifies B and records A as rejected.

### 15.2 Decisions taken in this design

Each decision says what was decided, why, and what was rejected. Sam can overturn any of them; the section named in each one says what would change.

**Acceptance case.**

- The problem: the requirement's example, the Brotli CVE (CVE-2026-111497), names only `Google` / `Brotli` in its CNA record. Before NVD's analysis, nothing in the data says Node is affected, so no Node rule can match it on day one.
- Decided: the acceptance test uses a Node CVE whose CNA record names Node. In production that is, for example, CVE-2026-123866, published 2026-11-11 with only a CNA record. In tests it is a copy of CVE-2026-56847's CNA entry with NVD's data removed (section 12).
- For a flaw in a library that products bundle, like Brotli, the day-one rule must name the library (`google:brotli`).
- Rejected: keeping the Brotli example, which cannot pass.
- Why it is not Sam's question: the evidence leaves no other test that exercises the requirement. Sam confirmed it with the requirements (15.1).

**No watchlist product item in this work** (section 9).

- Decided: the rule field covers the requirement. One rule can list every product a lab runs (`affected.cpe_product in [...]`).
- Rejected for now: a "product" watchlist item type, which would let several rules and digests share one list. It needs a database migration, API and web-page changes, and an addition to the alert-event listing added in PR 233.
- Why it is not Sam's question: nothing asked for it beyond the requirement's title, and the project's rule is not to build what is not needed yet. It can be added later without changing anything built here.

**Nearby CNA names do not match** (section 3.3).

- The problem: the version check also looks at CNA rows whose product merely contains a product's name under the same vendor, for example F5's "NGINX Plus" when checking nginx. It uses them only to refuse to say "not affected".
- Decided: rules do not match on them.
- Rejected: matching them, which would alert nginx users for NGINX Plus, NGINX Ingress Controller and other F5 products.
- Why it is not Sam's question: the products the lab runs are in the name table, so nearby names would add noise and catch nothing the table misses for those products.

**No `dsl_version` bump** (section 4.3).

- The problem: correlation changes what existing rules with an ecosystem and a package condition match. PLAN.md §10.5 says such a change bumps the rule-language version and keeps the old behaviour for old rules.
- Decided: no version bump. Old rules get the new, correct behaviour.
- Rejected: keeping the old behaviour, which is the bug the requirement asks to fix.
- Why it is not Sam's question: the project has no users, and its rules forbid backward-compatibility code without Sam's approval. A bump would be exactly such code. Section 4.3 states the effect: CVEs that stop matching send "no longer matches" notices.

**Package conditions stay independent of each other** (section 4.2).

- Decided: each package condition must match on the same row as the rule's ecosystem conditions. Two package conditions may match different rows. So "npm, package a, package b" means "a CVE affecting npm package a and npm package b".
- Rejected: requiring every package condition and ecosystem condition to match one row. Then "package a and package b" could never match anything.
- Why it is not Sam's question: the requirement asks only that the ecosystem and the package describe the same package, and the rejected reading removes a useful rule while adding nothing.

**Exact package match with no ecosystem is allowed** (section 5.3).

- The problem: a rule like "package name is exactly openssl", with no ecosystem, has to look in every ecosystem. An earlier form of the query took 10.5 s, close to the 14 s limit.
- Decided: allowed, with a warning from the validate endpoint.
- Measured: the form being built takes 217 ms cold on PostgreSQL 18, which can use the index this way.
- Rejected:
  - refusing it in `and` rules;
  - a new index, which costs a write on each of 7.5 million package rows at every update.
- Revisited if: the PostgreSQL 15 measurement in section 13 takes over 5 s, because PostgreSQL 15 to 17 cannot use the index this way.

**CNA entries that list every version as unaffected still match** (section 3.3).

- The problem: some CNA records list a product only to say no version of it is affected.
- Decided: such an entry still makes a product rule match.
- Reasons:
  - a rule with no version condition asks only whether the CNA names the product;
  - judging versions is the job of version conditions (MATCH-3);
  - CNA "unaffected" statements were found unreliable when the version check was designed.
- Cost: on the kept data, 3,149 such entries on 1,648 CVEs, none under the six products the lab most needs.
- Rejected: skipping them, which would also make a rule depend on version data that nothing re-checks when it changes.

**Ecosystems compared exactly** (section 4.1).

- The problem: PLAN.md §10.2 says rule comparisons ignore case. Today's code lower-cases ecosystem names before comparing them, which stops the database using its index on them.
- Decided: compare ecosystem names exactly, and add a clarifying line to §10.2.
- This changes no result. The validator accepts only the official spelling of an ecosystem name (`npm`, `PyPI`, `Debian:13`), and feeds' names are converted to the same spelling when they are stored, so the case of both sides is already fixed.
- Rejected: keeping the lower-casing, which costs the index and gains nothing.

**Never-matching ecosystem conditions are refused at save** (section 8).

- The problem: with correlation, a rule such as "ecosystem npm, ecosystem PyPI, package x" needs one package row that is in both npm and PyPI, which cannot exist.
- Decided: saving such a rule is an error that says why. A rule whose ecosystem conditions share an ecosystem, such as `Debian` with `Debian:13`, is allowed.
- Rejected: a warning. Today warnings reach only the validate endpoint, so a warning would never be seen when a rule is created or edited.

**Notifications after a name-table edit** (section 3.4).

- The problem: when a later code change edits the table of product spellings, old CVEs can start or stop matching rules. The step that re-checks them is built with the first such edit, not now; a test forces that.
- Decided for that step: it notifies for newly matched CVEs published in the last 30 days, and records older ones silently, as a new rule's first scan does (pitfall NOTIFY-1).
- Rejected:
  - notifying for all, which could send hundreds of alerts about old CVEs at once;
  - notifying for none, which would hide a recent CVE that the old table missed.
- Why it is not Sam's question now: the step is not built in this work. Whoever builds it can raise it again with the edit in hand.

## 16. Delivery

One pull request to `dev`, in commits: export the name lookup, value parser and key builders from `internal/check`, move the two index-expression helpers into it, and add the two names; the CVE-set form and `CompiledRule.Where` with the package correlation and `eq`/`in`; `affected.cpe_product`; the re-check signal (migration reviewed with `schema-review` and written with `migration`, then merge, handler and batch changes); PLAN.md. `material_hash` and its golden hashes do not change. `/pitfall-check` before the evaluator commit, `/plan-check` against PLAN.md §10 before merge.

## Appendix A. Measured statements

Run read-only (`SET default_transaction_read_only = on`) with `EXPLAIN (ANALYZE, COSTS OFF)` on the kept complete ingest, 2026-11-13. `<range a|o|h>` stands for `(left(m.cpe_normalized, 512) COLLATE "C" >= 'cpe:2.3:<part>:linux:linux_kernel:' AND left(m.cpe_normalized, 512) COLLATE "C" < 'cpe:2.3:<part>:linux:linux_kernel;')`; for Node, the same with `nodejs:node.js`. `<status>` is `COALESCE(lower(cves.status), '') NOT IN ('rejected', 'withdrawn')`. "Recent" is `(SELECT array_agg(cve_id) FROM (SELECT cve_id FROM cves ORDER BY date_modified_canonical DESC LIMIT 5000) x)::text[]`.

Realtime, `linux:linux_kernel`, `and` (0.28 ms); the batch row replaces `ARRAY['CVE-2024-26581']` with "recent" in all three places, the `or` rows add `OR cves.in_cisa_kev` to the membership test:

```sql
SELECT cves.cve_id FROM cves
WHERE cves.cve_id IN (
        SELECT m.cve_id FROM cve_cpe_matches m
        WHERE m.vulnerable AND m.cve_id = ANY(ARRAY['CVE-2024-26581']) AND (<range a> OR <range o> OR <range h>)
        UNION ALL
        SELECT a.cve_id FROM cve_cna_affected a
        WHERE a.cve_id = ANY(ARRAY['CVE-2024-26581'])
          AND ((left(lower(a.vendor), 256) COLLATE "C" = 'linux' AND left(lower(a.product), 256) COLLATE "C" = 'linux kernel')
            OR (left(lower(a.vendor), 256) COLLATE "C" = 'linux' AND left(lower(a.product), 256) COLLATE "C" = 'linux_kernel')))
  AND <status> AND cves.cve_id = ANY(ARRAY['CVE-2024-26581'])
LIMIT 5001;
```

Dry-run: the same with no `cve_id = ANY(...)` filter anywhere; the Node rows use Node's three ranges and the CNA names `nodejs` / `node`, `nodejs` / `nodejs`, `nodejs` / `node.js`, and add `AND lower(cves.severity) IN ('critical','high')` where the row says so. Saved-search shape: the `linux:linux_kernel` dry-run with only `<range a>`, `<range o>` and the name `linux` / `linux kernel`, and `ORDER BY cves.date_modified_canonical DESC, cves.cve_id DESC LIMIT 51`.

Package rows in section 5.1's array form, with `<folded name>` the `CASE` expression of `ecosystem.FoldedNameSQL`:

```sql
-- no ecosystem, eq openssl, two arms: 217 ms cold, 16 ms warm (skip scan on cve_affected_packages_check_idx)
SELECT cves.cve_id FROM cves
WHERE cves.cve_id IN (
        SELECT cap.cve_id FROM cve_affected_packages cap
        WHERE (cap.ecosystem = 'PyPI' AND <folded name> = ANY(ARRAY['openssl']))
           OR (cap.ecosystem <> 'PyPI' AND <folded name> = ANY(ARRAY['openssl'])))
  AND <status> LIMIT 5001;
-- npm with in [lodash, express, axios], one arm, 4.7 ms:
--   WHERE cap.ecosystem = ANY(ARRAY['npm']) AND <folded name> = ANY(ARRAY['lodash','express','axios'])
```

Package rows with the value folded per row (the earlier form, not built):

```sql
-- Debian and openssl, 0.90 s
SELECT cves.cve_id FROM cves
WHERE cves.cve_id IN (
        SELECT cap.cve_id FROM cve_affected_packages cap
        WHERE (cap.ecosystem = 'Debian' OR cap.ecosystem LIKE 'Debian:%')
          AND (CASE WHEN cap.ecosystem = 'PyPI' THEN regexp_replace(lower(cap.package_name), '[-_.]+', '-', 'g') ELSE lower(cap.package_name) END)
            = (CASE WHEN cap.ecosystem = 'PyPI' THEN regexp_replace(lower('openssl'), '[-_.]+', '-', 'g') ELSE lower('openssl') END))
  AND <status> LIMIT 5001;
-- no ecosystem, 10.5 s: the same without the ecosystem line
-- npm and lodash with the index expression, 0.52 ms:
--   EXISTS (SELECT 1 FROM cve_affected_packages cap WHERE cap.cve_id = cves.cve_id
--           AND cap.ecosystem = 'npm' AND <folded name expression> = 'lodash')
-- ecosystem neq npm with severity critical, 243 ms:
--   NOT EXISTS (SELECT 1 FROM cve_affected_packages cap WHERE cap.cve_id = cves.cve_id
--               AND (cap.ecosystem = 'npm' OR cap.ecosystem LIKE 'npm:%')) AND lower(cves.severity) = 'critical'
```
