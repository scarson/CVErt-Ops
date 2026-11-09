# Design: the version check endpoint (MATCH-1)

Date: 2026-11-08. Author: Claude, for Sam. Status: for Sam's review. No implementation code or migration exists yet.

## 1. Goal and scope

`POST /api/v1/orgs/{org_id}/check` answers, for a list of exact component versions: which advisories affect this version, which range matched, and what version fixes it. It is for components that per-host scanners cannot see, such as Node, PHP and .NET in runner tool caches. Scripts, the planned API-client CLI (`check` command) and the planned MCP server (`check_components` tool) are its callers.

**The failure to design against is a wrong "not affected".** It tells someone to stop looking. Every rule below that has to choose picks "affected" or "cannot evaluate" over "not affected".

**Not in scope:** joining distro records to their CVE (requirement DATA-3, section 6), scoped API keys (AUTH-3), per-key rate limits (AUTH-7), a version condition in alert rules, and Windows build comparison (DATA-8).

**Evidence.** Code was read at `origin/dev` commit `bbc7440`. Upstream data was read on 2026-11-08 from `api.osv.dev`, `cveawg.mitre.org` and the NVD API, and from the golden fixtures in this repository. Query plans were measured on PostgreSQL 18 with synthetic data (section 9). **None of this has run against a full ingest of live feeds.** Section 13 lists what to measure when one exists.

The data rules come from `dev/plans/2026-11-08-cve-range-data-batch-design.md` section 9 (four rules for this endpoint). Section 4 of this document extends the third rule to data sources that design did not cover.

## 2. Findings that shaped the design

| Finding | Evidence | Consequence |
|---|---|---|
| OSV names distro **source** packages. `php` on `Ubuntu:26.04:LTS` has no records; `php8.5` has four. | OSV API query for each name. | The acceptance example naming `php` cannot pass as written. See section 6. |
| Binary package names exist only in Ubuntu's `ecosystem_specific.binaries`, which is not stored. Debian records have no binary list. | OSV records for `php8.3` on Ubuntu and `curl` on Debian. | A binary name finds nothing, which would read as a clean answer unless handled (section 6). |
| Package rows for distro advisories already exist, under `UBUNTU-CVE-*`, `DEBIAN-CVE-*` and `USN-*` IDs. | The OSV adapter stores them; real records carry the correct fixed version. | The endpoint looks up by package, so it can answer without the join. |
| KEV and EPSS are written to the `CVE-*` row. A `UBUNTU-CVE-*` row is a different row, and merge resolves each row alone. | `internal/feed/kev/adapter.go`, `internal/merge/resolve.go`. The requirement lists CVE-2026-109618 and CVE-2026-109619 as in KEV. | Read from its own row, the acceptance example's Ubuntu record reports `in_cisa_kev: false` for an exploited CVE (section 6). |
| A CNA's `defaultStatus: unaffected` is not reliable. CVE-2026-56847 lists `26.5.0` with `lessThanOrEqual: 26.5.0` and default `unaffected`, while NVD records 26.0.0 to 26.5.0 as vulnerable. | CVE record and NVD API. | Read literally, Node 26.4.0 is "not affected" on a CVE that affects it. CNA data must never clear a version (section 4.3). |
| `defaultStatus: affected` is also unreliable. CVE-2024-4577 lists ranges per PHP branch with default `affected`, so a fixed version falls through to "affected". | CVE record. | The default status can neither clear nor condemn a version. |
| Multi-branch `changes[]` cannot be read literally. CVE-2024-7347 (nginx) says unaffected at 1.26.2 and 1.27.1 inside one range, so a literal reading clears 1.27.0, which is affected. CVE-2021-44228 alternates status across `changes[]`. | CVE record, golden MITRE archive. | Only versions below the lowest `changes[].at` can be read (section 4.3). |
| Node CNA records state no fix: `{version: "24.0", lessThan: "24.*"}` for every major line. | CVE-2024-27980 and CVE-2025-23166. | Wildcard upper bounds cannot be evaluated, and they must not block NVD's answer forever (section 4.4). |
| CNA and CPE names differ for most products the endpoint is for: `nodejs:node.js` against `nodejs` / `node`, `php:php` against `PHP Group` / `PHP`, `f5:nginx` against `F5` / `NGINX Open Source`, `python:python` against `Python Software Foundation` / `CPython`. | CVE records and NVD criteria. | Comparing names directly finds almost nothing (section 4.5). |
| No index serves any of the three lookups. | Query plans (section 9). | One migration adds three indexes. |
| The NVD cursor does not say when the first walk finished. | `internal/feed/nvd/adapter.go`, `computeNextCursor`. | The cursor gains a field (section 5). |

## 3. Inputs

### 3.1 Request

```json
{
  "items": [
    {"id": "runner-node", "cpe": "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", "version": "24.22.0"},
    {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"},
    {"purl": "pkg:deb/ubuntu/php8.5@8.5.4-0ubuntu1.4?distro=ubuntu-26.04"}
  ]
}
```

Each item holds exactly one of three forms. `id` is optional, is at most 128 characters, and is echoed back.

### 3.2 Package forms

`ecosystem` must pass `ecosystem.Valid`: exact OSV names, as elsewhere in the API. The stored row's `package_name` is compared after `ecosystem.FoldPackageName`, the same folding merge and the watchlist use.

A distro ecosystem must name a release. `Debian` alone is refused with `ecosystem_release_required`, because the batch design's "bare name matches every release" is right for an alert rule and meaningless for one exact version. `internal/version` accepts a bare `Debian` today, so the check is here.

**purl mapping**, parsed with `packageurl-go` (section 14):

| purl type | Ecosystem | Name |
|---|---|---|
| `npm` | `npm` | `@scope/name` or `name` |
| `pypi` | `PyPI` | `name` |
| `golang` | `Go` | `namespace/name` (`stdlib` stays `stdlib`) |
| `maven` | `Maven` | `group:artifact` |
| `cargo`, `gem`, `nuget`, `hex`, `pub` | `crates.io`, `RubyGems`, `NuGet`, `Hex`, `Pub` | `name` |
| `composer` | `Packagist` | `vendor/name` |
| `deb` | from namespace and `distro` | `name` |
| `apk` | `Alpine:v<major>.<minor>` from `distro` | `name` |
| anything else, including `rpm` | refused: `unsupported_purl_type` | |

Red Hat's OSV strings carry a repository stream (`Red Hat:enterprise_linux:8::appstream`) that a purl does not hold, so `rpm` must use the `ecosystem` form.

**A purl identifies a distro release through its `distro` qualifier:**

| `distro` value | Ecosystem | Source of the form |
|---|---|---|
| `ubuntu-26.04` | `Ubuntu:26.04:LTS` | Trivy writes `<family>-<release>` |
| `ubuntu-25.10` | `Ubuntu:25.10` | `:LTS` is added for an even year with month 04 |
| `debian-13`, `debian-13.1` | `Debian:13` | Point release dropped |
| `3.20.3`, `alpine-3.20` (type `apk`) | `Alpine:v3.20` | Trivy writes the plain release; patch level dropped |
| `trixie`, `resolute` and similar | Looked up in a short table of current releases | OSV's own purls and the purl specification's examples use codenames |
| missing or not recognised | refused: `distro_required`, `distro_not_recognised` | |
| names a different distribution from the purl namespace | refused: `conflicting_distro` | `pkg:deb/ubuntu/...?distro=debian-13` has no single answer |

Ubuntu Pro streams (`Ubuntu:Pro:24.04:LTS`) have no purl form and must use the `ecosystem` form. For `deb`, an `epoch` qualifier is prepended to the version when the version has none. Leaving it off sorts the version too low, and a range without an epoch can then wrongly clear or condemn it. A purl with no version is refused with `version_required`. Qualifiers other than `distro` and `epoch` are ignored, and a purl with a subpath is refused with `invalid_purl`.

### 3.3 CPE form

`cpe` must be a CPE 2.3 formatted string with `part`, `vendor` and `product` set to literal values. It is lower-cased to match `cpe_normalized`, which the NVD adapter also lower-cases. The version comes from `version`, or from the CPE's own version component. If both are given and differ, the item is refused with `conflicting_version`. Only `part:vendor:product` selects rows. The other attributes do not narrow the lookup (section 4.2).

One leading `v` or `V` before a digit is removed from a CPE-form version, because `node --version` prints `v24.22.0` and `version.CheckNumeric` accepts only digits and dots. Package ecosystems need no such step: their syntax rules already accept `v` where the ecosystem uses it. The response's `component.version` is the version as compared. No other rewriting is done: `go1.26.0` in the `Go` ecosystem answers `invalid_version`, which tells the caller what to fix.

### 3.4 Limits and errors

| Limit | Value | Reason |
|---|---|---|
| Items per request | 500 | A weekly run is a few hundred distinct components. |
| `purl` | 1,024 characters | |
| `cpe`, `name` | 512 characters | |
| `version` | 256 characters | Matches `internal/version`'s `maxVersionLen`. |
| `id` | 128 characters | |

An item holds one form, so the longest is a `purl` with an `id`, about 1.2 KB of JSON. At these limits a request of plain text is at most about 600 KB, so the global 1 MiB limit (`middleware.RequestSize`) does not refuse a request that respects the item cap. A value written mostly as JSON `\u` escapes could reach it, and gets the 413 below.

| Problem | Result |
|---|---|
| Body over 1 MiB | 413, from the middleware |
| Malformed JSON | 400 |
| `items` missing, empty or over the cap | 422 |
| One item invalid | 200. That item has `status: "invalid"` and an `error`; the others are answered. |
| One item has more candidate rows than the per-item limit (section 9) | 200. That item is `cannot_evaluate`, reason `too_many_candidates`; the others are answered. |
| Candidate rows over 200,000 in total (section 9) | 422 with `candidate_limit_exceeded`. The caller splits the request. |
| All check slots in use (section 9) | 503 with `Retry-After`. Nothing was read. |
| 30-second limit reached | 503. No partial answer, because a partial read cannot say which items lost rows. |

The watchlist replace endpoint fails a whole request for one bad item because it writes. This endpoint is read-only, and one malformed component should not cost a script the other 499 answers.

## 4. Verdicts

### 4.1 Package ranges

Rows come from `cve_affected_packages`, matched on the exact ecosystem and folded name.

| Row | Outcome for the version |
|---|---|
| `range_type = GIT` | Ignored if the advisory has any other row for this component. If it has only `GIT` rows, cannot evaluate. |
| `SEMVER` type in an ecosystem whose native order is not SemVer | Compared as SemVer, through a new `version.CheckSemver`. A version SemVer cannot read is cannot evaluate. |
| Ecosystem with no comparator (`Root:*`, `SwiftURL`, `GitHub Actions` and others) | Cannot evaluate. |
| No bounds, or empty `introduced` | Cannot evaluate. `version.Check` reports `ErrInvalidRange`. |
| Anything else | `version.Check`. |

**Combining rows for one advisory** (the third rule of the batch design):

- **Affected** if any row reports Affected.
- **Not affected** only if at least one row reported Not affected and none reported cannot evaluate.
- **Cannot evaluate** otherwise.

**Several fixes under one `introduced`.** The OSV adapter turns `[{introduced: 0}, {fixed: A}, {fixed: B}]` into `(0, A)` and `("", B)`. The second row answers cannot evaluate, so a version below A is Affected with no fix claimed, and a version at or above A is cannot evaluate. In the golden archive this shape occurs in five `Root:*` records and two `GIT` ranges. `Root:*` has no comparator, so those answers are cannot evaluate anyway. I recommend leaving this as it is: repairing the adapter would invent a meaning for a shape the OSV schema does not define. Section 13 measures whether it occurs in ecosystems that can be compared.

### 4.2 NVD CPE ranges

Rows come from `cve_cpe_matches` with `vulnerable = true`. Comparison is `version.CheckNumeric`: dotted numbers only, because a product has no ecosystem to define its order.

| Row | `version.Range` |
|---|---|
| Version component `*` with any `versionStart*` or `versionEnd*` | `Introduced` = start, or `0` if none. `Fixed` = `versionEndExcluding`. `LastAffected` = `versionEndIncluding`. |
| `versionStartExcluding` | Stored as an inclusive `Introduced`, as the batch design does for GHSA: that one version reports affected. |
| A literal version component and no range | `Introduced` and `LastAffected` both that version. |
| Version component `*` with no bounds, or `-` | Cannot evaluate, reason `no_version_bounds`. The requirement names "missing range" as a cannot-evaluate case. |

**Two known over-reports, both accepted because they fail towards "affected":**

- Rows are matched on `part:vendor:product`, so a row narrowed by `update`, `sw_edition` or `target_sw` still applies. For example, `microsoft:.net:11.0.0:preview1` reports the release `11.0.0` as affected.
- `cve_cpe_matches` does not keep NVD's AND/OR configuration tree, so "A only when running on B" reports as affected on any platform.

A version that is not dotted numbers, such as `1.24rc1` or `8.5.4-0ubuntu1.4` given in CPE form, is cannot evaluate.

### 4.3 CNA `affected[]`

**Rule: CNA data can report Affected and can name a fix. It can never report Not affected.** Section 2 has the real records behind this.

Comparator, from `versionType`:

| `versionType` | Comparator |
|---|---|
| `semver` | SemVer rule (`npm` syntax gate) |
| `python` | PEP 440 |
| `maven` | Maven |
| `rpm` | RPM |
| `custom` or absent | `CheckNumeric` |
| `git` or anything else | Not comparable |

Bounds are normalised first. A wildcard lower bound `8.1.*` becomes `8.1`. A free-text `version` such as `>= 20.0.0, <= 20.10.27` (common in GitHub-issued records, for example CVE-2024-41110 for moby) is read with the GHSA range grammar, which moves from `internal/feed/ghsa` to `internal/version`.

| Entry | Version position | Result |
|---|---|---|
| `status: affected`, comparable bounds or single version | Inside | **Affected.** Fix candidate: `lessThan`, if given. |
| | Outside | No statement. |
| `status: affected` with `changes[]`, lowest `at` is L | From `version` up to L | **Affected.** Fix candidate: L. |
| | Equal to a `changes[].at` whose status is `unaffected` | No statement. |
| | Any other version at or above L | Indeterminate. |
| `status: affected`, upper bound contains `*` | At or above the lower bound (for `X.*`, on branch X) | Indeterminate. |
| Not comparable (`unspecified`, `n/a`, non-numeric under `custom`, `git`) | | Indeterminate. |
| `status: unaffected` or `unknown`; `defaultStatus` of any value | | No statement. |

Read over all of a product's entries: Affected if any entry says so; otherwise cannot evaluate, with reason `cna_cannot_clear`. A CVE whose only data is a CNA record therefore answers Affected or cannot evaluate, never Not affected.

### 4.4 When NVD and CNA both have data

For a CPE-form item and one advisory:

1. Affected if an NVD row or a CNA entry reports Affected.
2. Cannot evaluate if any NVD row answers cannot evaluate.
3. If NVD has at least one comparable row and all report Not affected, the result is **Not affected**, unless a wildcard CNA entry on branch `X.*` contains the version and no NVD row has a bound on branch `X`. Then it is cannot evaluate.
4. With no NVD rows, the CNA result stands.

The third step extends the batch design's third rule, which treats any cannot-evaluate as blocking. Without the extension, every Node version named by a CNA wildcard stays cannot evaluate forever, and the acceptance example "`24.22.1` returns nothing for it" could never pass. The branch check keeps the protection that matters: if NVD analysed lines 22 and 24 and the CNA also names line 26, version 26.x stays unanswered instead of being cleared.

Worked examples, real records:

| Version | NVD | CNA | Result |
|---|---|---|---|
| Node 24.22.0, CVE-2026-111497 | `[23.0.0, 24.22.1)` contains it | Names Google Brotli, not Node | Affected, fixed 24.22.1 |
| Node 24.22.1, same CVE | Outside every range | None | Not affected |
| nginx 1.27.0, CVE-2024-7347 | Depends on its rows | Above lowest `at`: indeterminate | NVD decides; never cleared by CNA |
| Node 26.4.0, CVE-2026-56847 | `[26.0.0, 26.5.0]` contains it | No statement | Affected, no fix claimed (the upper bound is inclusive) |
| Same, before NVD analyses it | None | No statement | Cannot evaluate |

### 4.5 Finding CNA rows for a CPE

A small table in code maps CPE `vendor:product` to CNA `(vendor, product)` pairs, compared in lower case. It is seeded with the products this endpoint exists for, from the real records in section 2. Without a table entry, the CPE's own vendor and product are compared directly (with `_` read as a space), which finds `openssl:openssl`.

| CPE | CNA vendor and product |
|---|---|
| `nodejs:node.js` | `nodejs` / `node` |
| `php:php` | `php group` / `php` |
| `f5:nginx`, `nginx:nginx` | `f5` / `nginx open source` |
| `microsoft:.net`, `microsoft:.net_core` | `microsoft` / `.net 8.0`, `.net 9.0`, `.net 10.0` |
| `postgresql:postgresql` | `n/a` / `postgresql`, `postgresql` / `postgresql` |
| `python:python` | `python software foundation` / `cpython` |

A product with no table entry and no direct match has no CNA evidence, so a CVE NVD has not analysed cannot be seen at all. **Such a product cannot be cleared:** an answer that would be `not_affected` becomes `cannot_evaluate`, reason `cna_product_not_mapped` (section 4.6). `affected` is unaffected, and `no_advisory_found` carries the same name as a warning. A status-keyed script would miss a warning, which is the reason a distro lookup with no rows is not `no_advisory_found` either. Adding a table row is the cure, and costs one line.

**What remains unseen.** A CVE that NVD has not analysed and whose CNA record names the product differently from the table, or names none, is invisible for a product that does have a mapping. A new .NET major is one example until its row is added. `not_affected` therefore means "not in any analysed or CNA-named advisory we hold". The API description says so, and no flag can close this gap.

CNA `packageName` is not used to find rows for package-form items. GHSA and OSV cover those, and they are what the data-complete flag measures.

### 4.6 Item status

Advisories that report Not affected are counted, not listed. That is what "`24.22.1` returns nothing for it" means.

| Condition, checked in order | `status` |
|---|---|
| Input invalid | `invalid` |
| More candidate rows than the per-item limit | `cannot_evaluate`, reason `too_many_candidates`, with no advisories listed. The rows read are not all of them, so neither a verdict nor a fix can be trusted. |
| Any advisory Affected | `affected` (true even on incomplete data) |
| Any advisory cannot evaluate | `cannot_evaluate` |
| Advisories found, all Not affected, data incomplete | `cannot_evaluate`, reason `data_incomplete` |
| Advisories found, all Not affected, CPE item with no CNA name | `cannot_evaluate`, reason `cna_product_not_mapped` |
| Advisories found, all Not affected | `not_affected` |
| No advisories, distro ecosystem | `cannot_evaluate`, reason `distro_package_not_found` |
| No advisories | `no_advisory_found` |

The item's `reason` is set only when one of the item-level rows above produced the status. When the status comes from an advisory that answered cannot evaluate, the item's `reason` is null and each listed advisory carries its own.

## 5. "No advisory found" is not "not affected"

`no_advisory_found` means the corpus has no record naming this component. Consumers must treat it as "nothing known", and the MCP tool description and CLI output must say so. It is a distinct status even when data is complete, because a product can simply be absent from every feed.

**`data_complete`** is true when every feed an item depends on has finished a full walk:

| Item form | Feeds | Read from `feed_sync_state.cursor_json` |
|---|---|---|
| Package, distro ecosystem | `osv` | OSV `LastModified` non-zero. GHSA has no distro records, so it cannot make these answers more or less complete. |
| Package, any other ecosystem | `ghsa` and `osv` | GHSA `Since` non-empty; OSV `LastModified` non-zero (batch design section 9) |
| CPE | `nvd` | New field `caught_up` (below) |

Only OSV and GHSA write `cve_affected_packages`, so no other feed bears on a package item. A feed an operator never runs stays incomplete, which is correct: the `feeds` list in the response names it.

NVD needs its own signal, because the cursor looks the same at every stage. `computeNextCursor` will set `CaughtUp: true` on the cursor it returns with `LastPage`, and every later cursor carries it forward. Clearing the cursor to refill resets it, which is correct. MITRE is not required, because NVD relays the CNA record (262 of 262 real records matched when this was measured for DATA-2).

**Stale feeds** count as incomplete: a feed with no successful run for 7 days reports `complete: false`. This covers paused feeds and long outages, when "not affected" would mean "not affected as of two weeks ago". It goes one step beyond the batch design's "walk finished" definition and is a decision for Sam (section 15).

Cursors are read before ranges. A feed that completes during the request can then only make the answer more cautious.

"Complete" means the walk finished. It does not mean every record parsed, because adapters log and skip unreadable records.

## 6. Distro answers without DATA-3

**Recommendation: ship without DATA-3.** The endpoint looks up by package, and the package rows already exist under each distro advisory's own ID. Real data for the acceptance example:

```
Ubuntu:26.04:LTS / php8.5, version 8.5.4-0ubuntu1.4
  UBUNTU-CVE-2026-109618  fixed 8.5.4-0ubuntu1.5
  UBUNTU-CVE-2026-109619  fixed 8.5.4-0ubuntu1.5
  USN-8948-1              fixed 8.5.4-0ubuntu1.5
```

The response returns `advisory_id` (the stored record, usable with `GET /cves/{id}`) and `cve_id`. `cve_id` equals `advisory_id` for a `CVE-` record, is taken from the ID for `UBUNTU-CVE-*`, `DEBIAN-CVE-*` and `ALPINE-CVE-*` (each covers one CVE by construction; 259 of 259 real Debian and Ubuntu records checked agree with their `upstream` field), and is `null` for `USN-*` and `DSA-*`, which cover several. DATA-3 fills those later with no change to the response shape. The `ALPINE-CVE-*` rule rests on the ID's construction alone; no real Alpine record was checked.

**Exploit data comes from the CVE, not the distro record.** `in_cisa_kev` and `epss_score` belong to the `CVE-*` row (section 2), so a second read by the derived `cve_id` values fills them in, and sorting uses them. Where `cve_id` is `null`, both are `null`, which means "not known", never false. `severity` and the CVSS scores stay those of the distro's own record, as the requirement for DATA-3 notes that distro records carry their own. An upstream CVE that was rejected does not remove the distro advisory: the distro record still states a fix, and leaving it fails towards "affected".

Counts are of advisory records. `USN-8948-1` and `UBUNTU-CVE-2026-109618` count as two, because without DATA-3 the server cannot say that the USN contains that CVE. The API description says "records", not "vulnerabilities".

DATA-3 would be needed first only if the endpoint had to start from a CVE ID, or had to map binary names. An agent asking "what fixes CVE-X on Ubuntu 26.04" calls this endpoint with the package and version, and reads the advisory whose `cve_id` is CVE-X. That needs the package name; DATA-3 would let it start from the CVE alone. Binary names are handled below.

**The acceptance example must change.** The requirement says `php` `8.5.4-0ubuntu1.4`. `php` is not a source package on Ubuntu 26.04, so no feed has it. The example that can pass names `php8.5`. Sam needs to accept this (section 15).

**Binary names.** A caller with `dpkg-query` output has names like `php8.5-cli`, and a Debian or Ubuntu lookup with such a name finds nothing. Reporting `no_advisory_found` would read as clean to a script. So a zero-row lookup in a distro ecosystem answers `cannot_evaluate` with reason `distro_package_not_found`, and the description says to use the source package name. This also marks a real source package with no advisories as unanswered. That cost is small, because per-host distro matching stays with Trivy and few distro items will reach this endpoint.

## 7. Fix reporting

`fixed_version` is computed per advisory:

1. Candidates are the upper bounds of the ranges that report Affected for this version: package `fixed`, NVD `versionEndExcluding`, CNA `lessThan` or lowest `changes[].at`. A `last_affected` bound is not a candidate, because it does not say what fixes the problem.
2. Sort candidates in the component's order and take the lowest one that no range of the advisory reports as Affected and none reports as cannot evaluate. CNA entries are applied with the section 4.3 table and the section 4.4 steps: an indeterminate entry containing the candidate rejects it, unless NVD has a comparable row that section 4.4 lets stand in its place.
3. If no candidate passes, `fixed_version` is `null`.

Only ranges that contain the version contribute, so a Node 24.22.0 lookup considers `24.22.1` and never `22.23.4`. When two sources disagree (fixed in 1.2.3 and in 1.2.4), both ranges contain 1.2.0, 1.2.3 is still inside the second, and 1.2.4 is returned.

A range with `introduced = 0` has no branch, so a version on an old line can be told to move to a higher line. That is the correct reading of what the record states.

`fixed_version` means "the lowest version the advisory data no longer reports as affected". For 460 GHSA ranges of the form `< B` with no patch, a release at B may not exist. The stored row cannot tell those apart, so the API description uses this wording rather than promising a published fix.

## 8. Retracted records

A row joins to `cves`, and an advisory with `COALESCE(lower(cves.status), '') IN ('rejected', 'withdrawn')` is excluded from verdicts, the same test the alert paths use. This covers MITRE and NVD rejections in any case, and tombstones from a CVE whose every source row is withdrawn. A withdrawn advisory among live ones already contributes no rows (batch design section 5.3).

Excluded advisories are counted in `counts.retracted`, so a caller can see that one existed. An item whose only advisories are retracted is `no_advisory_found`.

## 9. Performance

One SQL statement per data source (packages, CPE rows, CNA rows), each joining `unnest` of the distinct keys in the request to its table and to `cves`. Identical items are looked up once.

**Indexes (next free migration number, `CONCURRENTLY`, no-transaction):**

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_packages_check_idx
    ON cve_affected_packages (ecosystem,
        (CASE WHEN ecosystem = 'PyPI' THEN regexp_replace(lower(package_name), '[-_.]+', '-', 'g') ELSE lower(package_name) END));
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cpe_matches_check_idx
    ON cve_cpe_matches ((cpe_normalized COLLATE "C"));
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cna_affected_check_idx
    ON cve_cna_affected ((left(lower(vendor), 256)), (left(lower(product), 256)));
```

- The package expression is `ecosystem.FoldedNameSQL`'s output, and the query is built from that function, so the two cannot drift. A test asserts the index definition matches.
- CPE rows are found by a range on the prefix (`>= 'cpe:2.3:a:nodejs:node.js:'` and `< 'cpe:2.3:a:nodejs:node.js;'`). `LIKE` with array parameters cannot use a btree. Taking the prefix as written also means escaped colons need no special handling.
- CNA `vendor` and `product` can each reach 2,048 characters, and a value over the btree row limit would fail the merge of that whole CVE. `left(..., 256)` keeps the key under the limit. The migration comment on `cve_cna_affected` already records this hazard.

**Measured**, PostgreSQL 18, 700,000 `cves`, 6 million package rows, 3 million CPE rows, 420,000 CNA rows, one package with 40,000 rows:

| Lookup | Keys | Rows | Today's indexes | With index |
|---|---:|---:|---|---|
| Packages | 300 | 58,423 | 10.9 s, parallel sequential scan and external sort | 0.25 to 0.41 s, one index scan per key |
| CPE | 100 | 8,836 | 13.8 s, join filter over 2.75 million rows | 0.72 s |
| CNA | 100 | 1,244 | 278 ms | 4 ms |

The plan was the same with a generic plan as with a custom plan. These were synthetic rows. The row counts are estimates of a full corpus, and the shape of real name distributions may differ.

Version comparison costs 5.2 µs for dpkg and 2.3 µs for numeric on the development machine, so 58,000 rows take about 0.3 s, before fix candidates are checked.

**Bounds.** Each statement reads each key through `CROSS JOIN LATERAL (... LIMIT 50001)`, still one statement per data source, with the key's position returned so rows can be attributed. A key that reaches 50,001 rows answers `cannot_evaluate`, reason `too_many_candidates`, for the items using it, and the other items are unaffected. Measured on the same synthetic data with 300 keys, one holding 90,000 rows: 110,951 rows in 0.7 to 1.6 s, one index scan per key under a `Limit`, the same plan generic and custom, and only that key at the limit.

The statement as a whole is read with `LIMIT 200001`. A request that reaches that limit fails as a whole with 422: a partial read cannot say which items lost rows, and a truncated read is exactly how a wrong "not affected" happens. The 200,000 figure is about twice the rows I expect from a request of a few hundred items, including one package the size of the Linux kernel; neither limit has been measured on real data (section 13).

Rows are read into memory, the transaction ends, and only then are versions compared, so no database connection is held for the comparison work. A process runs at most 4 checks at once, by the semaphore pattern `argon2Sem` uses, and a request that finds none free gets 503 with `Retry-After`. Each item lists at most 100 advisories (Affected first, then KEV, then score), with `advisories_truncated` set. Status and counts are always computed over all of them. Each advisory lists at most 20 matched ranges. The handler runs under a 30-second context limit.

The index adds write cost to the merge's delete-and-reinsert of child rows. That has not been measured. Section 13 covers it.

## 10. Authorisation and limits

- **Role:** viewer. It reads only global CVE data. The route is org-scoped so that RBAC, the tier and the org rate limit apply.
- **Route:** `r.With(srv.RequireOrgRole(RoleViewer)).Post("/check", srv.checkComponentsHandler)`, a chi route like the other org routes, with a spec-only registration.
- **Transaction helper:** `withOrgRawTx`, because the query is built from `ecosystem.FoldedNameSQL`. `cve_*` and `feed_sync_state` have no RLS, so `withBypassTx` is unnecessary and would widen the transaction's rights. `WorkerTx` is never used from handlers.
- **Not stored or logged:** the components are a picture of what an org runs. Items are neither persisted nor logged. There is no audit entry, as for other read-only routes.
- **Scopes (AUTH-3) later:** when scopes exist, this route gains `cves:read` beside its role check, as one more entry in the `operationAccess` table and one middleware on the route. The response does not change.
- **Rate limits (AUTH-7):** `orgRateLimitMiddleware` already counts a request once regardless of its item count, which is what AUTH-7 asks for batch endpoints. A weekly run of a few hundred components is one or two requests. **Nothing in AUTH-7 has to ship with this.** The per-key bucket and `X-RateLimit-*` headers remain separate work.
- **Cost per request:** because a request counts once, the rate limit does not bound its cost. Section 9 adds a process-wide limit on concurrent checks.

## 11. API contract

```json
{
  "data_complete": true,
  "feeds": [
    {"name": "ghsa", "complete": true, "last_success_at": "2026-11-08T10:00:00Z"},
    {"name": "osv", "complete": true, "last_success_at": "2026-11-08T09:40:00Z"},
    {"name": "nvd", "complete": true, "last_success_at": "2026-11-08T10:15:00Z"}
  ],
  "results": [
    {
      "index": 0,
      "id": "runner-node",
      "status": "affected",
      "reason": null,
      "component": {"kind": "product", "part": "a", "vendor": "nodejs", "product": "node.js", "version": "24.22.0"},
      "data_complete": true,
      "counts": {"affected": 1, "cannot_evaluate": 0, "not_affected": 3, "retracted": 0},
      "advisories": [
        {
          "advisory_id": "CVE-2026-111497",
          "cve_id": "CVE-2026-111497",
          "verdict": "affected",
          "reason": null,
          "fixed_version": "24.22.1",
          "matched_ranges": [
            {"evidence": "nvd_cpe", "cpe": "cpe:2.3:a:nodejs:node.js:*:*:*:*:-:*:*:*", "introduced": "23.0.0", "fixed": "24.22.1"}
          ],
          "severity": "HIGH",
          "cvss_v3_score": 7.5,
          "epss_score": 0.01,
          "in_cisa_kev": false
        }
      ],
      "advisories_truncated": false,
      "warnings": [],
      "error": null
    }
  ]
}
```

Scores above illustrate the shape only. `in_cisa_kev` and `epss_score` are nullable: `null` means the record has no CVE to read them from (section 6).

**Stable values for the CLI and MCP tool:** `results` is in request order, and `index` and `id` identify each item. `advisory_id` works with `GET /cves/{id}`. `status`, `verdict`, `reason`, `evidence`, `warnings` and `error.code` are closed enumerations declared in the spec.

| Field | Values |
|---|---|
| `status` | `affected`, `not_affected`, `cannot_evaluate`, `no_advisory_found`, `invalid` |
| `verdict` | `affected`, `cannot_evaluate` |
| `reason` | `unknown_version_scheme`, `invalid_version`, `invalid_range`, `commit_ranges_only`, `no_version_bounds`, `cna_cannot_clear`, `cna_product_not_mapped`, `data_incomplete`, `distro_package_not_found`, `too_many_candidates` |
| `evidence` | `package_range`, `nvd_cpe`, `cna` |
| `warnings` | `cna_product_not_mapped` |
| `error.code` | `invalid_form` (not exactly one of the three forms), `invalid_ecosystem`, `ecosystem_release_required`, `invalid_purl`, `unsupported_purl_type`, `distro_required`, `distro_not_recognised`, `conflicting_distro`, `invalid_cpe`, `version_required`, `conflicting_version`, `value_too_long` |
| `component.kind` | `package`, `product` |

**OpenAPI tests.** `POST /orgs/{org_id}/check` needs:

- `registerCheckSpecOps` in `registerAllSpecOps`, and `roleOp("viewer")` in `operationAccess`, for `TestOpenAPISpec_MatchesRoutes` and `TestOpenAPISecurity_TableCoversEveryOperation`.
- Operation ID `check-components`, default status 200.
- Named Go body types, because `TestOpenAPISpec_SchemaNamesFitGeneratedClients` rejects anonymous names: `CheckRequest`, `CheckItem`, `CheckResults`, `CheckItemResult`, `CheckAdvisory`, `CheckMatchedRange`, `CheckComponent`, `CheckCounts`, `CheckItemError`, `CheckFeedStatus`. A body named `CheckComponentsResponse` would collide with the type a generated client makes for this operation.
- `maxItems:"500"` on `items`, with a test tying it to the handler's constant, as `TestOpenAPISpec_ReplaceItemsCapMatchesHandler` does.
- A request with no body returns 400 for a permitted role, which is what `TestOpenAPISecurity_MatchesEnforcement` needs.
- `openapi.json` and the web `schema.d.ts` regenerated.

**Layout.** A new `internal/check` package holds input parsing and the verdict functions, as pure code with no database. `internal/store/check.go` reads the candidates, `internal/api/check.go` is the handler. `internal/version` gains `CheckSemver`, a way to ask whether an ecosystem needs a release, and the moved range grammar.

## 12. Test data

Golden data already holds real records for most acceptance cases. `testutil.SeedCorpus` does not write feed cursors, so tests that need `data_complete: true` write them with `UpsertFeedSyncState`.

| Case | Input | Expected | Data |
|---|---|---|---|
| Node, affected | CPE `nodejs:node.js`, `24.22.0` | CVE-2026-111497, fixed `24.22.1` | `SeedCorpus` (golden NVD) |
| Node, fixed | same, `24.22.1` | Advisory absent, `not_affected` | `SeedCorpus` + cursors |
| Same, data incomplete | no cursors | `cannot_evaluate`, `data_incomplete` | `SeedCorpus` |
| .NET branches | CPE `microsoft:.net`, `9.0.21` | Fixed `9.0.22`, not `8.0.33` | `SeedCorpus` |
| Distro | `Ubuntu:26.04:LTS` / `php8.5`, `8.5.4-0ubuntu1.4` | The two CVEs, fixed `8.5.4-0ubuntu1.5`; USN with `cve_id` null | Three real OSV records added to the golden archive |
| Distro, fixed | same, `8.5.4-0ubuntu1.5` | `not_affected` | Same |
| Distro, wrong name | `php`, then `php8.5-cli` | `cannot_evaluate`, `distro_package_not_found` | Same |
| Multi-branch package | `Packagist` / `drupal/core`, on one branch | Fix from that branch | `SeedCorpus` (`DRUPAL-CORE-2018-002`) |
| Retracted | Package or CPE of a rejected or withdrawn record | Excluded, `counts.retracted` | `SeedCorpus` where a rejected or withdrawn golden record keeps rows; otherwise a targeted patch |
| No comparator | `ROOT-OS-DEBIAN-12-CVE-2025-40110` | `cannot_evaluate`, `unknown_version_scheme` | `SeedCorpus` |
| CNA only | CPE `fastify:fastify`, `5.12.3` and `5.12.6` (`CVE-2026-107832`, not yet analysed by NVD) | Affected, fixed `5.12.6`; then `cannot_evaluate`, never Not affected | `SeedCorpus` |
| **CNA must not clear** | CVE-2026-56847 with NVD rows removed, `26.4.0` | `cannot_evaluate` | Targeted patch, real CNA values |
| **`changes[]` must not clear** | CVE-2024-7347, `1.27.0`, no NVD rows | `cannot_evaluate` | Targeted patch, real CNA values |
| Wildcard, branch covered | Node CNA `24.0` to `24.*`, NVD on 24, `24.22.1` | `not_affected` | Targeted patch |
| Wildcard, branch not covered | Same, NVD lacks 26, `26.1.0` | `cannot_evaluate` | Targeted patch |
| `GIT` only | Hand-built patch | `cannot_evaluate`, `commit_ranges_only` | Targeted patch |
| `v` prefix | CPE `nodejs:node.js`, `v24.22.0` | Same as `24.22.0`; `component.version` is `24.22.0` | `SeedCorpus` |
| Exploit data on a distro record | `php8.5` example, with KEV and EPSS on the `CVE-2026-*` rows | `UBUNTU-CVE-*` shows `in_cisa_kev: true`; USN shows `null` | Same three records plus a targeted KEV patch |
| Product with no CNA name | CPE with NVD rows, all Not affected, no table entry, no direct CNA rows | `cannot_evaluate`, `cna_product_not_mapped` | Targeted patch |
| Distro depends only on OSV | OSV cursor set, GHSA cursor absent, distro item | `data_complete: true` | `UpsertFeedSyncState` |
| Per-item limit | One package over the limit, one normal item, limit lowered by the test | First `cannot_evaluate`, `too_many_candidates`; second answered | Targeted patch |

Adding three records to the golden archive adds lines to `golden_material_hashes.json` and changes corpus counts. Existing pins must not move.

The verdict functions also get table tests for each row of sections 4.1 to 4.4 and section 7, and purl mapping gets a table test for each row of section 3.2. A break test, run once during implementation, removes the CNA-must-not-clear rule and confirms the two bold cases fail.

## 13. Measure on the first full ingest

- Share of items and advisories answering `cannot_evaluate`, by reason.
- Whether the "several fixes under one `introduced`" shape occurs outside `Root:*` and `GIT`.
- Real row counts per package, to confirm the 50,000 and 200,000 limits.
- Write cost of the three new indexes during a backfill.
- `cve_affected_packages_eco_pkg_idx` may become redundant.
- How often a looser CNA rule would be wrong: for CVEs with one product on each side and NVD analysis, how often NVD reports a version at or past the CNA's highest clean bound. The golden data is too small to decide this (section 15).
- Share of CPE lookups blocked by a vulnerable row with no version bounds. In the golden NVD page, 11 of 503 vulnerable rows have `*` and no bounds.
- How many CPE items answer `cna_product_not_mapped`, and for which products. Those are the table rows worth adding.

## 14. Dependency

`github.com/package-url/packageurl-go`, for purl parsing. `dependency-check`, 2026-11-08:

| Check | Result |
|---|---|
| Repository | Not archived; under the `package-url` organisation, which owns the specification |
| Last commit / release | 2026-08-24 / `v0.1.7`, 2026-08-21 |
| Open issues | 7 |
| Known vulnerabilities | None in OSV for this module; none found in search |
| Licence | MIT |
| Transitive dependencies | None |

Verdict: approved. The alternative is about 60 lines of our own parsing. The library is cheap to adopt and handles percent-decoding and type-specific rules the specification defines. `osv-scalibr/purl`, in a module already used here, wraps the same library, so it would add the same dependency.

## 15. Decisions for Sam

Each row gives the strongest argument for the alternative and why the recommendation stands against it.

| Decision | Recommendation | Alternative | Strongest case for the alternative | Why the recommendation stands |
|---|---|---|---|---|
| Distro answers before DATA-3 | Ship without it. Return `advisory_id`, a `cve_id` derived where the ID states it, and exploit data read from that CVE. | Build DATA-3 first. | A `USN-*` record has no CVE, so no KEV signal. One vulnerability counts as two records. An agent cannot start from a CVE ID. | These cost ranking and labels, not verdicts. The same fix appears on the `UBUNTU-CVE-*` record, which does carry its CVE. DATA-3 needs its own design of the join, and fills `cve_id` later with no change to the response. |
| The acceptance example naming `php` | Change it to `php8.5`. | Keep `php` and add a table of distro metapackages. | The requirement is the contract, and `php` is the name a person would type. | The version in the example belongs to `php8.5`. As far as I know the binary `php` comes from `php-defaults` with its own numbering (general knowledge, not checked), so a table would compare a version against the wrong package, and needs upkeep per release. |
| A distro name with no rows | `cannot_evaluate`. | `no_advisory_found` with a warning. | A real source package with no advisories is common. Marking it unanswered teaches people to ignore the status, and `no_advisory_found` is already documented as "nothing known". | `dpkg-query` output is binary names in bulk, and a script branches on status. The reason is distinct, so a script can treat it separately. Few distro items are expected here. |
| CNA data can never clear a version | Keep this rule. A CVE before NVD analysis stays `cannot_evaluate` after patching. | Trust `defaultStatus: unaffected`. Or clear a version above the highest clean `lessThan`. | NVD's backlog can leave a patched version unanswered for weeks, at the moment someone wants to confirm a patch. Clean bounds are probably right most of the time. | Of the 3 golden records with clean CNA bounds, one product and NVD analysis, one (CVE-2026-56847) would be wrongly cleared. That sample is tiny, so section 13 measures it on a full ingest. The rule can loosen later with data. A wrong clearance cannot be taken back. |
| NVD's answer over a CNA wildcard, when NVD has that branch | Allow it, extending the batch design's third rule. | Keep the rule strict and change the acceptance example for `24.22.1`. | A bound on the branch shows that NVD analysed the CVE. It is not proof about later versions, and the CNA may be right that no fix exists. | An NVD upper bound on that branch is a specific statement of where the problem ends. Without this step no Node version can ever clear, and the requirement's own example cannot pass. |
| CPE to CNA name table | A short table in code. | Caller supplies CNA names. Or NVD only. Or derive the table from CVEs that have both. | A hand table covers only what someone added. Deriving it from co-occurrence would cover the long tail with no upkeep. | A wrong derived pair applies another product's ranges and reports false Affected. Callers should not need CNA spellings. NVD only loses disclosure-day answers. Derivation can be added later behind the same lookup. |
| A CPE product with no CNA name | Cannot be cleared: `cannot_evaluate`, `cna_product_not_mapped`. | Answer `not_affected` with a warning. | Products NVD has analysed thoroughly answer `cannot_evaluate` until someone adds a row, and the warning is machine-readable. | A CVE NVD has not analysed is invisible for that product, so `not_affected` would be the wrong answer this design exists to avoid. A status-keyed script misses a warning. The cure is one table row. |
| Stale feeds count as incomplete | Yes, at 7 days without success. | Walk-finished only, with `last_success_at` for callers to judge. | An upstream outage of a week turns every clean answer into `cannot_evaluate` when probably nothing changed, and the caller already has the timestamp. | Seven days is longer than ordinary outages. A status-keyed script gets an honest answer without reading timestamps. The threshold is one constant. |
| CPE row with `*` and no bounds | `cannot_evaluate`, as the requirement says for a missing range. | Affected, NVD's literal meaning. | NVD does say every version, and this design prefers "affected" when it has to choose. | The requirement names a missing range as cannot evaluate. Affected never clears after patching, so it is a permanent alarm no one can act on. `cannot_evaluate` does not clear either. |
| Item cap and limits | 500 items. Over 50,000 rows for one item answers `cannot_evaluate` for that item. Over 200,000 rows in total fails the request. | 1,000 items. Or total limit only. | A host SBOM has thousands of components, so a client must split. A total limit alone is simpler by one clause. | The requirement sizes a run at a few hundred components, and the CLI can split. Without the per-item limit, one package larger than the total limit could never be answered and would fail every request that names it. Each limit is one constant. |
| Concurrent checks | 4 per process, by the `argon2Sem` pattern; beyond that 503. | Rely on the org rate limit. | A self-hosted single-tenant install rarely runs two checks at once, so this is code for a future problem. | A request counts once against the rate limit whatever it costs. At the limit it holds an estimated 100 MB (200,000 rows of about 500 bytes) and a database connection for seconds. The pattern exists and is about ten lines. |
| Purl parser | `packageurl-go`. | Our own parser, about 60 lines. | This is a security product and we use a small part of the library. Its normalisation can change under us. | Percent-decoding and per-type rules are where hand-written parsers go wrong. It has no transitive dependencies. A table test for each mapped type shows any behaviour change on upgrade. |

**Checked and left as they are:** failing the whole request for one bad item (simpler for a client, but this route is read-only and one typo should not cost 499 answers); an org-scoped route for global data (a global route would escape RBAC, the tier and the org rate limit); listing Not-affected advisories as proof (the requirement says such an advisory "returns nothing", and counts report them).

Left out, and easy to add later: an item-level "lowest version that clears every advisory", which `fixed_version` per advisory lets the server compute by the section 7 method; CNA `packageName` lookups for package-form items; the CNA `packageURL` field, which the feed does not store.

## 16. Delivery

One pull request with small commits, because no part is useful alone: the migration and NVD `caught_up` field; `internal/version` additions; `internal/check` with table tests; the store read; the handler and spec; golden additions. The usual review skills apply when the code exists: `schema-review` for the migration, `security-review` for the route, `pitfall-check`, `plan-check` against `PLAN.md` §9.2. `PLAN.md` §16 and Appendix B gain the endpoint.

This design has not had an independent review.
