# Design: product conditions and correlated package conditions in alert rules (MATCH-2)

Date: 2026-11-13. Author: Claude, for Sam. Status: draft for Sam's review. No implementation code or migration exists.

Review ledger: `dev/plans/reviews/2026-11-13-product-match-rules-design.ledger.md`.

Review record: the first review run stopped after 6 rounds (three independent rounds found 15, 14 and 11 defects), with 11 open findings noted in place. A second run, an independent review by Claude Fable at Sam's request followed by a discussion of its disputed findings, resolved all 11 notes and its own 11 findings: each is fixed in the text or is an open question in section 15. The second run's fixes have not had an independent re-read; defects found while building come back to this document as findings. Section 15's open questions are Sam's to answer.

## 1. Requirements

Status: unconfirmed. Paraphrased from requirement MATCH-2 of the private homelab integration requirements; Sam has not confirmed this wording.

1. **Product field.** The alert rule language gets a field for a CPE vendor and product, so a rule can say "this product, with severity high or above" without a watchlist. Version conditions come later (requirement MATCH-3, not designed here).
2. **Correlation.** `affected.ecosystem` and `affected.package` are matched within one affected-package entry, not anywhere in the CVE.
3. **Exact match.** `affected.package` gets an exact-match operator. This design reads "exact" as equal after the ecosystem's own name folding (section 4.1, open question 7).
4. **Watchlists.** The requirement's title names watchlists as well as rules; its text and acceptance case concern rules only.
5. **Acceptance.** A rule `{affected.cpe_product eq nodejs:node.js, severity in [critical, high]}` matches the Brotli CVE (CVE-2026-111497) on the day the CNA record lands, before NVD has analysed it. Section 2 shows that this CVE's CNA record does not name Node; open question 1 proposes a Node-named CVE instead. "On the day the CNA record lands" also depends on how often the MITRE and NVD feeds are polled, which this design does not change.

Why it matters: Node, PHP and .NET in runner tool caches are invisible to per-host scanners, so a rule on the product is the only alert for them, and NVD analyses only a minority of new CVEs within weeks (section 2).

## 2. Findings that shaped the design

Measured on 2026-11-13 against the complete ingest kept from Phase 2 of the version check plan (`dev/plans/2026-11-09-version-check-endpoint-plan.md`; about 2.6 million CVEs; PostgreSQL 18), read-only. The project supports PostgreSQL 15 and later; plans were measured on 18 only. Code read at `dev` `5598af6`.

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

A CNA row matches whatever its versions' statuses say, including an entry whose every version is `unaffected`; the version check (`internal/check/cna.go` `readEntry`) reads such an entry as no statement. This is recommended, not settled (open question 9):

- A rule with no version condition asks whether the CNA names the product. Status belongs with version conditions (requirement MATCH-3), which will read `versions` anyway.
- Filtering on status would make a match depend on the `versions` JSON, which neither option of section 7 tracks, so a CNA changing `unaffected` to `affected` would be another unevaluated change.
- It is not inconsistent with filtering NVD rows on `vulnerable`: `vulnerable = false` marks a platform or configuration CPE ("runs on"), not a statement that the product is unaffected.
- Cost: an alert for a CVE whose CNA lists the product only to say it is not affected. On the kept ingest 3,149 entries on 1,648 CVEs list versions that are all `unaffected` with no `affected` default; none is under the six products the name table maps.

Not read:

- `cve_affected_cpes`. It holds every CPE string any source names: NVD's criteria, including platform CPEs (`vulnerable = false`), the CPEs a CNA lists in its own record (`affected[].cpes`, `internal/feed/mitre/adapter.go`), Red Hat's CPEs in CPE 2.2 form and MSRC product names. Reading it roughly doubles the matches for operating systems (section 2). The CNA-supplied CPEs would be a day-one source: 5,162 CVEs have a CPE 2.3 row there that is not one of NVD's and no NVD match. But the table records no source, so they cannot be read apart from NVD's platform CPEs without a schema change, and the CNA's vendor and product names already cover most such records. CPE watchlist items still read the table (section 9).
- The version check's nearby names (a CNA row under the product's vendor whose product contains a fragment, such as `F5` / `NGINX Plus` for `f5:nginx`). The check endpoint uses them only to refuse a clean answer. Matching them in a rule would alert for other products of the same vendor. Open question 4.
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
- The step an edit must ship with: on worker start, if the table's digest differs from the one stored in the database, run evaluation, with delivery, of every active rule that has an `affected.cpe_product` condition, over the CVEs with a CNA row under any vendor in a changed entry or a vulnerable CPE match row under any CPE spelling in a changed entry (adding a spelling makes a rule on one spelling read rows under the other), then store the new digest. `date_modified_canonical` does not move, because it must keep meaning "materially changed" for API polling and digests (section 7). The first edit that changes a match builds this step.
- The test only proves the digest was touched, not that the step was built or run; it is a prompt to the author and reviewer, not a proof.

### 3.5 Alert behaviour over a CVE's life

For a Node CVE such as CVE-2026-123866:

1. The CNA record arrives (MITRE, or NVD's relay before analysis). The CVE is new, so its first `material_hash` runs realtime evaluation, and the rule fires. If another feed (OSV, GHSA, KEV) delivered the CVE first without a CNA entry, the CNA rows arrive on a later merge, which is step 4's case.
2. NVD analyses the CVE and adds CPEs. `cve_affected_cpes` is a `material_hash` input, so the hash changes and the rule fires a second time for the same CVE. This is the existing meaning of a material change (PLAN.md §5.3, affected CPE set). It means two notifications per product CVE that NVD analyses later.
3. NVD flips a CPE between vulnerable and not vulnerable with the same criteria string. The hash does not change, so a rule that starts or stops matching because of the flip is not evaluated until the next material change. Pitfall NOTIFY-2 rejects leaving this open, and the remedy is the same choice as step 4: section 7's hash option could add the vulnerable product set in the same one-time move, and its separate-signal option covers both. Open question 2.
4. The CNA changes its product names, with nothing else material. Section 7.

### 3.6 Alternatives not chosen

- **Separate `affected.vendor` and `affected.product` fields**, correlated like the package fields. A vendor alone is not a usable key: the CNA and NVD spell vendors differently (`php group` against `php`, `the node.js project` against `nodejs`), so a vendor value would match one source and miss the other, and only the pair can go through the name table.
- **Extend the CPE watchlist item to read CNA names**, with no rule field. The requirement asks for a rule that works without a watchlist, and changing the CPE item would change what existing items match, including their platform CPEs (section 9).

## 4. Package conditions: exact match and correlation

### 4.1 Exact match

`affected.package` gains `eq` and `in`. A value matches a stored row when the names are equal after folding for the row's ecosystem (`ecosystem.FoldPackageName`, the folding merge and the watchlist package match use). So `Foo_Bar` matches PyPI `foo-bar` and npm `foo_bar`, not npm `foo-bar`. "Exact" therefore means equal after the ecosystem's own folding, never a comparison of the stored spelling (open question 7 asks Sam to confirm this reading). An empty or whitespace-only value is refused. Section 5.1 gives the SQL.

Ecosystems are compared exactly, where today's compiler and `watchlistExpr` lower-case them. Rule values must be canonical OSV names already (`ecosystem.Valid`), and stored values are canonical since the ecosystem vocabulary was unified at ingest, so the two readings agree on stored data; the exact form lets `cve_affected_packages_check_idx` serve `ecosystem = ANY`, which `lower(ecosystem)` cannot. It departs from PLAN.md §10.2, which requires case-insensitive `eq`; section 11 amends §10.2 for ecosystems, and open question 10 asks Sam to accept that or keep `lower()` at the index's cost.

### 4.2 Correlation

Under `logic: and`, each `affected.package` condition must hold on one `cve_affected_packages` row together with every `affected.ecosystem` condition that uses `eq` or `in`. `{affected.ecosystem eq Debian, affected.package eq openssl}` means "a Debian row (any release) for openssl".

- Package conditions are not correlated with each other. `{affected.ecosystem eq npm, affected.package eq a, affected.package eq b}` means "an npm row for a, and an npm row for b", so a rule can still ask for a CVE that affects both. This is the narrower of two readings; open question 6 has the other.
- `affected.ecosystem` with `neq` or `not_in` stays a condition on the whole CVE: "the CVE has no row in this ecosystem". Read per row it would mean "some row in another ecosystem", which says nothing useful.
- A rule with ecosystem conditions and no package condition matches as today: each ecosystem condition on its own.
- Under `logic: or`, each condition is matched on its own, as today. "Npm, or a package named lodash" has no single row to correlate.
- `affected.cpe_product` is not correlated with package conditions. It reads different tables, and a rule that names both a product and a package asks for a CVE that has both.

As compile rules, for an `and` rule:

1. Each package condition becomes one set (section 5.1) holding its own predicate and the predicate of every `eq` or `in` ecosystem condition in the rule.
2. When the rule has a package condition, its `eq` and `in` ecosystem conditions are not emitted again on their own: every package set already requires a row in those ecosystems.
3. When the rule has no package condition, each `eq` or `in` ecosystem condition becomes its own set, which matches as today.
4. `neq` and `not_in` ecosystem conditions are always emitted on their own, as `NOT EXISTS`.

Under rule 1, two `eq` or `in` ecosystem conditions beside a package condition must both hold on the package's row, so `{ecosystem eq npm, ecosystem eq PyPI, package contains x}`, which today matches a CVE with an npm row, a PyPI row and an `x` row, matches nothing. The validator warns about that shape (section 8).

### 4.3 Existing rules change meaning

An existing `and` rule with an ecosystem and a package condition matches fewer CVEs once this ships. When a CVE that no longer matches is next evaluated (realtime on its next hash change, or a batch or EPSS run that includes it), its open event resolves and a resolution notification is sent ("no longer matches the rule's conditions"). Until then, events opened under the old reading stay open; if section 7's hash change ships, CVEs whose hashes move are re-evaluated as feeds redeliver them, and many of these events resolve then. PLAN.md §10.5 says a changed meaning bumps `dsl_version` and keeps the old compiler. This design does not: the project has no users, and keeping the uncorrelated reading would keep the wrong answer. Without a version, reverting the correlation is a code revert: rules widen again from each CVE's next evaluation, and a CVE whose event was resolved by this change reopens at the same hash and notifies (PLAN.md §10.4). Open question 5.

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

A row is one of a value's other products when its lower-cased vendor equals the other product's vendor, and its lower-cased product equals the other product's name or, for a prefix, starts with it and is followed by nothing or by a character that is not an ASCII letter or digit. In SQL the following character is tested with `!~ '^[a-z0-9]'` on the lower-cased product, and `isOtherProduct` changes from `unicode.IsLetter`/`IsDigit` to the same ASCII test, so both sides agree whatever the database's character type. Every name and other product in the table is ASCII; the only change in behaviour is that a prefix followed by a non-ASCII letter now counts as a word boundary. On the kept ingest no Microsoft product name has a non-ASCII character after either `.NET Framework` prefix (0 rows), so no stored row changes.

PostgreSQL's `lower()` follows the database's character type, while names in the table and rule values are ASCII and are lower-cased in Go. Only stored non-ASCII vendor or product text can therefore compare differently between deployments: such a name, whose non-ASCII letter lower-cases to an ASCII letter in one locale, matches a table name in that locale and not in another.

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

`$ecosN` holds an ecosystem condition's values. The bracketed release arm is emitted only when the condition names a base ecosystem that takes a release suffix (`Debian`, `Ubuntu`, `Packagist` and the others in `internal/ecosystem`'s `takesSuffix`, which gains an exported accessor), and `$releasesN` then holds those base names, LIKE-escaped, followed by `:%`, so `Debian` also matches `Debian:13`, as today. A line with no release arm leaves `ecosystem = ANY` for the index to serve. Every list is one array parameter, whatever its length.

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

`queryCandidates` keeps appending `cves.cve_id = ANY(?)` itself; each set repeats the same list. Squirrel numbers every placeholder separately, so the array is sent once per copy: two copies per product condition (one per branch), one per package condition, and one outer. A rule at the limits carries about 200 copies; a batch chunk is 5,000 IDs, so that rule sends about a million IDs per statement. Section 13 measures this case; a common rule of a few conditions carries a handful of copies.

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
- refusing `affected.package` `eq` or `in` in an `and` rule with no `eq` or `in` ecosystem condition. The operators are new, so no stored rule breaks, and under `and` the fix is to add the ecosystem. Under `or` nothing correlates, so refusing there would remove `eq` from every `or` rule. Open question 8.

The `or` rows above ran with hashed SubPlans. A SubPlan is hashed only when its estimated size fits in `hash_mem` (default `work_mem` 4 MB × `hash_mem_multiplier` 2; the project sets neither), so a wide `or` product rule may fall back to a SubPlan rescanned for each CVE row; section 13 measures it.

Appendix A holds the measured statements, so the implementation plan can repeat these rows on the kept ingest once the code exists (section 13). The batch rows above compare different products across the two forms, so the batch cost of the set form against today's form is not known; the set form was chosen on the dry-run rows and the equal realtime rows.

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

**Recommendation: add the CNA product identity to `material_hash`.** `MaterialFields` gains `affected_products`, tagged `json:"affected_products,omitempty"` and left nil when a CVE has no CNA rows: the distinct pairs of CNA vendor and product, lower-cased as the match compares them, with a missing value as an empty string, sorted by vendor and then product in byte order. `omitempty` and the nil slice keep the hash of a CVE with no CNA rows unchanged, as the range-data design did for `last_affected`; `ComputeMaterialHash` turns its other nil slices into `[]`, which this field must not copy, or every CVE's hash would move. PLAN.md §5.3 already treats "what is affected" as material (packages and the CPE set); this adds the CNA's statement of it. Lower-casing keeps the NVD relay and the MITRE copy of one entry from moving the hash when they differ only in case. Spaces are not trimmed, because the match does not trim either: the 721 stored rows with surrounding spaces match no name, and a CNA that removes the spaces can make such a row match, which should move the hash.

Cost: the hash of every CVE with CNA rows (405,809 of about 2.6 million) changes on its next merge. Each such merge runs realtime evaluation of every active rule, synchronously in the ingest loop, as any hash change does. On an instance with active rules, each such CVE that matches a rule fires once more at its new hash, spread over the weeks in which feeds deliver those CVEs again; an OSV backfill would deliver most of them at once. The golden material hashes are regenerated in the same pull request. Each moved hash also moves the CVE's `date_modified_canonical`, so API pollers and daily digests see 405,809 CVEs as materially modified over those weeks, and the batch path evaluates each of them once more. After that, the cost continues: every later CNA product edit is a material change that re-fires every rule matching the CVE, not only product rules, and because both copies of a CNA entry are kept (MITRE's and NVD's relay, `resolveCNAAffected`), one edit can move the hash twice, once as each copy arrives. With no users this is accepted, but Sam's own instances may have rules. Reverting the change later moves the same hashes back, at the same cost.

**Alternative: a separate evaluation signal.** Merge could compare the CNA product set (and NVD's vulnerable flags, section 3.5 step 3) before and after, and on a difference run realtime evaluation and record the CVE for the next batch run, without changing `material_hash`. This closes both gaps with no corpus-wide re-fire, and a new match still fires, because no event exists for that rule and CVE at the current hash. The cost is a second change-tracking mechanism: realtime is best-effort, so the batch path needs its own record of such CVEs (a column or a queue beside `date_modified_canonical`, which must keep meaning "materially changed" for API polling), and a rule whose match flips this way would resolve and reopen at one hash. It is the better choice if re-fires on existing instances matter more than one more mechanism.

**NVD's vulnerable flag** (section 3.5 step 3) belongs to the same choice. With the hash option, `MaterialFields` can carry the set of vulnerable CPE `part:vendor:product` keys in the same one-time move, at the cost of moving the hash of every NVD-analysed CVE rather than only those with CNA rows. With the separate signal, merge compares that set as well.

**Version conditions** (requirement MATCH-3) will read CNA versions and NVD ranges, which neither option tracks as designed here. The separate signal extends to them by comparing more fields; the hash option would need another corpus-wide hash move when version conditions land, unless MATCH-3 adds a separate signal then.

Leaving both gaps open is not an option: pitfall NOTIFY-2 rejects documenting a correctness gap in alerting instead of closing it. Open question 2.

## 8. Validation and messages

Errors stop a save. Messages follow the existing `ValidationError` list (`internal/alert/dsl/validator.go`), one entry per problem, with the condition index. Today warnings reach a caller only through `POST .../alert-rules/validate`: create and PATCH (`internal/api/alert_rules.go`) act on blocking errors alone, and saved searches and AI search drop warnings. So a warning cannot be relied on to stop a rule shape. Open question 11 asks whether create and PATCH return warnings, or the several-ecosystems shape below (which section 4.2 makes match nothing) becomes an error; the recommendation is an error, because a rule that can never match is a mistake whoever wrote it.

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
| An `and` rule with a package condition and more than one `affected.ecosystem` condition using `eq` or `in` | warning, rule-level (error if open question 11 is answered so) | `every ecosystem condition must hold on the same package row, so only an ecosystem all of them name can match; use one "in" condition if any of them is enough` |
| An operator other than `eq` or `in` on `affected.cpe_product` | error | the existing `operator %q is not valid for field %q` |
| A product with no row in the name table | warning | `no other CNA spelling is known for "x:y"; before NVD analyses a CVE, it matches only if the CNA record names vendor "x" and product "y"` (with `_` shown as a space where the own names do) |
| `affected.package` `eq` or `in` with an empty or whitespace-only value | error | `value must not be empty` |
| `affected.package` `eq` or `in` in an `or` rule, or in an `and` rule that has no `affected.ecosystem` condition with `eq` or `in` | warning (error in the `and` case if open question 8 is answered so) | `without an ecosystem condition in an "and" rule, this match reads every ecosystem, which is slow before PostgreSQL 18` |

`affected.cpe_product` joins `selectiveFields`, so a regex rule with a product condition is allowed without a watchlist. The validator needs no database; the warning about unmapped products comes from the table in code.

## 9. Watchlists

**Recommendation: no new watchlist item type in this work.** `affected.cpe_product in [...]` lists a lab's products in one rule, which is what the requirement's text asks for. A product item type (`item_type = 'product'`, a `vendor:product` column, matched by the same set SQL as the rule field) would let one list feed several rules and digests, which PLAN.md §9.1 anticipates ("vendors/products, optional convenience"). It needs a migration, API and SPA changes to the watchlist views. Open question 3.

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
- §10.2's case-insensitive `eq`: ecosystems are compared exactly, because rule values and stored values are both canonical names, if open question 10 is accepted.
- §10.5: record that the correlation change ships without a `dsl_version` bump, if open question 5 is accepted.
- §5.3, if open question 2 is accepted: the CNA product set is material.
- Appendix A's `cve_cpe_matches` and `cve_cna_affected` entries: alert rules read them.

## 12. Tests

TDD per the project rules. Integration tests use testcontainers through `testutil.NewTestDB`.

**Unit (`internal/alert/dsl`, `internal/check`):**

- Value parsing: valid values from section 2's escaped rows (`1und1:1\&1_online_storage`), `\.` dropped, uppercase lower-cased, KELVIN SIGN refused, `nodejs:node.js\` refused, each error row of section 8, 255 and 256 characters; a rule with 50 product values over several conditions passes and one with 51 fails; a rule with 100 conditions passes and one with 101 fails.
- Each refusal the rule adds to the check's parser (section 3.1) is also refused by the check in a full CPE.
- `affected.package eq " "` is refused.
- The unmapped-product warning appears for `example:widget` and not for `nodejs:node.js`; the several-ecosystems warning appears for `{ecosystem eq npm, ecosystem eq PyPI, package contains x}`.
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
- If open question 2 is accepted: a CNA product change alone moves `material_hash` and fires realtime; a case-only difference between two copies does not; a CVE with no CNA rows keeps its hash. Golden hashes regenerated in one commit, and the review check on that diff is that a pin moves only for a CVE with CNA rows.
- Late-binding: after a CVE ID move, a product rule matches the new ID (the CNA and CPE match rows move with it).

## 13. Measure during implementation

On the kept complete ingest, with the built code:

- the section 5.3 rows for realtime (one CVE, `linux:linux_kernel`), batch (5,000 IDs), dry-run (Node, `linux:linux_kernel`) and the saved-search shape;
- the limit rule: 50 product values, the 50 products with the most vulnerable CPE rows (the largest is `linux:linux_kernel`), spread over enough conditions to reach 100, measured realtime against one CVE, dry-run, and **batch with a 5,000-ID chunk**, where the candidate array is sent about 200 times (section 5.2), including planning time;
- an `or` rule with 50 of those products in dry-run, checking that the set SubPlan stays hashed (section 5.3);
- the array form of section 5.1's package predicate: `npm` with an `in` of 50 names, `Debian` with `eq openssl`, and `eq` and `contains` with no ecosystem;
- the realtime, batch and dry-run rows again on PostgreSQL 15. Every test helper and compose file pins `postgres:18-alpine`, and PostgreSQL 18 adds planner features these plans use or may use (btree skip scan, `OR` lists turned into arrays), so the supported range 15 and later is unmeasured until this runs;
- a full activation scan of the limit rule: it must finish well inside the 15 minutes after which `SweepZombieActivations` fails the job and sets the rule to `error` (about 2,600 pages of 1,000 IDs, so under about 340 ms a page, which must also cover `cveExists` and `InsertAlertEvent`, two statements per matched CVE).

Thresholds that go back to Sam before merge: a realtime row over 5 ms; a batch chunk over 3 s, well under the 14 s statement timeout, because a failed batch statement holds the cursor for every rule for up to 30 runs (`batchMaxHeldRuns`); a dry-run over 5 s; an activation over 7 minutes. If the limit rule fails the batch threshold, the fallback is a lower limit on set-type conditions only (`affected.cpe_product`, `affected.package`, and `eq`/`in` ecosystem conditions in a rule with no package condition), which are the conditions that carry candidate-array copies; scalar conditions keep the limit of 100. A shared candidate CTE is not the fallback: a CTE referenced from several branches is materialised, and a join to it is the `unnest` shape section 5.1 measured as a sequential scan.

## 14. Not in scope

- Version conditions in rules (requirement MATCH-3).
- CNA `package_key` for `affected.package`. 3,905 CVEs have a CNA package key and no package row under that CVE, 573 of them with no GHSA or OSV source at all (measured on the kept ingest for Phase 4 of `dev/plans/2026-11-09-version-check-endpoint-plan.md`). A package rule could read them, but that changes what "package" means for a rule; a later change can add it.
- `neq` and `not_in` on `affected.cpe_product` (section 3.2).
- Showing CNA rows on the CVE detail page.

## 15. Open questions for Sam

1. **Acceptance case.** The requirement's example, the Brotli CVE, names only `Google` / `Brotli` in its CNA record, so no CNA-based rule for Node can match it before NVD analysis. Proposed acceptance: a Node CVE whose CNA names Node (CVE-2026-123866 live; a CNA-only copy of CVE-2026-56847 in tests). For bundled-library advisories like Brotli, the day-one rule names the library (`google:brotli`). Accept?
2. **How a change in CNA product names, or in NVD's vulnerable flag, gets evaluated** (sections 3.5 and 7). Leaving it open is not an option (pitfall NOTIFY-2). Options:
   - Add the CNA product set, and if wanted the vulnerable CPE set, to `material_hash` (recommended): one mechanism. Costs one more alert per matching CVE with CNA data on instances that already have rules, as feeds redeliver those CVEs; 405,809 CVEs shown as modified; afterwards a re-fire of every matching rule on each CNA product edit, sometimes twice. Adding the vulnerable set moves every NVD-analysed CVE's hash too. Version conditions (MATCH-3) may need another move.
   - A separate evaluation signal: no re-fires, closes both gaps and extends to MATCH-3's inputs, but a second change-tracking mechanism.
3. **Watchlist product item type** (section 9). Recommended later, as its own change, if a rule's `in` list is not enough.
4. **Nearby CNA names** (section 3.3). Recommended no: a rule on `f5:nginx` would also alert for NGINX Plus and other F5 nginx products before NVD analysis. Yes would trade that noise for the CNA spellings the table does not know.
5. **No `dsl_version` bump for correlation** (section 4.3). Recommended no bump: existing `and` rules with an ecosystem and a package condition narrow, and their CVEs that stop matching send resolution notifications.
6. **How far correlation reaches** (section 4.2). Recommended: each package condition is correlated with the rule's `eq`/`in` ecosystem conditions, and package conditions stay independent of each other, which is what the requirement names and keeps "affects both a and b" expressible. The alternative correlates every package and ecosystem condition on one row, so `{package eq a, package eq b}` matches nothing; it is simpler to state and has no use the narrower reading lacks.
7. **Requirements wording** (section 1). Section 1 paraphrases the private requirement. Confirm it, or correct it, so the design can be checked against it. In particular, confirm that "exact match" means equal after the ecosystem's own name folding (section 4.1), not equal to the stored spelling.
8. **`affected.package` `eq`/`in` with no ecosystem** (section 5.3). Options: refuse it in an `and` rule with no `eq`/`in` ecosystem condition, and allow it under `or`; or allow it everywhere with a warning. Recommended: allow it, because the form that will be built runs in 217 ms cold on PostgreSQL 18; revisit if the PostgreSQL 15 measurement of section 13 is slow. Refusing everywhere would remove `eq` from `or` rules and is not offered.
9. **CNA entries whose versions are all `unaffected`** (section 3.3). Recommended: they match, failing towards alerting; status belongs to version conditions. Cost: alerts where the CNA lists the product only to say it is unaffected (3,149 entries on 1,648 CVEs on the kept ingest; none under the six mapped products).
10. **Exact ecosystem comparison** (section 4.1). Recommended: compare ecosystems exactly and amend PLAN.md §10.2's case-insensitive `eq` for ecosystems, so the index serves; both sides are canonical names. The alternative keeps `lower()` and loses the index on the ecosystem column.
11. **Warnings at save** (section 8). Today only the validate endpoint returns warnings. Recommended: make the several-ecosystems shape an error, because it can never match. The alternative is to return warnings from create and PATCH too, which changes their response for every rule.

## 16. Delivery

One pull request to `dev`, in commits: export the name lookup, value parser and key builders from `internal/check`, move the two index-expression helpers into it, and add the two names; the CVE-set form and `CompiledRule.Where` with the package correlation and `eq`/`in`; `affected.cpe_product`; the material hash change if accepted, with golden hashes; PLAN.md. `/pitfall-check` before the evaluator commit, `/plan-check` against PLAN.md §10 before merge.

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
