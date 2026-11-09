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
| `trixie`, `resolute` and similar | Looked up in a short table of current releases | OSV's own purls and the purl specification's examples use codenames |
| missing or not recognised | refused: `distro_required`, `distro_not_recognised` | |

Ubuntu Pro streams (`Ubuntu:Pro:24.04:LTS`) have no purl form and must use the `ecosystem` form. For `deb`, an `epoch` qualifier is prepended to the version when the version has none. Leaving it off sorts the version too low, and a range without an epoch can then wrongly clear or condemn it.

### 3.3 CPE form

`cpe` must be a CPE 2.3 formatted string with `part`, `vendor` and `product` set to literal values. The version comes from `version`, or from the CPE's own version component. If both are given and differ, the item is refused with `conflicting_version`. Only `part:vendor:product` selects rows. The other attributes do not narrow the lookup (section 4.2).

### 3.4 Limits and errors

| Limit | Value | Reason |
|---|---|---|
| Items per request | 500 | A weekly run is a few hundred distinct components. |
| `purl` | 1,024 characters | |
| `cpe`, `name` | 512 characters | |
| `version` | 256 characters | Matches `internal/version`'s `maxVersionLen`. |
| `id` | 128 characters | |

At these limits a request is at most about 550 KB, so the global 1 MiB limit (`middleware.RequestSize`) cannot refuse a request that respects the item cap.

| Problem | Result |
|---|---|
| Body over 1 MiB | 413, from the middleware |
| Malformed JSON | 400 |
| `items` missing, empty or over the cap | 422 |
| One item invalid | 200. That item has `status: "invalid"` and an `error`; the others are answered. |
| Candidate rows over 200,000 (section 9) | 422 with `candidate_limit_exceeded`. The caller splits the request. |

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

A product with no table entry and no direct match returns NVD results only, and the item carries the warning `cna_product_not_mapped`. A new .NET major needs one more row here. Until then NVD still covers it, once analysed.

CNA `packageName` is not used to find rows for package-form items. GHSA and OSV cover those, and they are what the data-complete flag measures.

### 4.6 Item status

Advisories that report Not affected are counted, not listed. That is what "`24.22.1` returns nothing for it" means.

| Condition, checked in order | `status` |
|---|---|
| Input invalid | `invalid` |
| Any advisory Affected | `affected` (true even on incomplete data) |
| Any advisory cannot evaluate | `cannot_evaluate` |
| Advisories found, all Not affected, data complete | `not_affected` |
| Advisories found, all Not affected, data incomplete | `cannot_evaluate`, reason `data_incomplete` |
| No advisories, distro ecosystem | `cannot_evaluate`, reason `distro_package_not_found` |
| No advisories | `no_advisory_found` |

## 5. "No advisory found" is not "not affected"

`no_advisory_found` means the corpus has no record naming this component. Consumers must treat it as "nothing known", and the MCP tool description and CLI output must say so. It is a distinct status even when data is complete, because a product can simply be absent from every feed.

**`data_complete`** is true when every feed an item depends on has finished a full walk:

| Item form | Feeds | Read from `feed_sync_state.cursor_json` |
|---|---|---|
| Package | `ghsa` and `osv` | GHSA `Since` non-empty; OSV `LastModified` non-zero (batch design section 9) |
| CPE | `nvd` | New field `caught_up` (below) |

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

The response returns `advisory_id` (the stored record, usable with `GET /cves/{id}`) and `cve_id`. `cve_id` equals `advisory_id` for a `CVE-` record, is taken from the ID for `UBUNTU-CVE-*`, `DEBIAN-CVE-*` and `ALPINE-CVE-*` (each covers one CVE by construction; 259 of 259 real Debian and Ubuntu records checked agree with their `upstream` field), and is `null` for `USN-*` and `DSA-*`, which cover several. DATA-3 fills those later with no change to the response shape.

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

**Bounds:** rows are read with `LIMIT 200001`. A request that reaches the limit fails as a whole with 422, because a partial read cannot say which items lost rows, and a truncated read is exactly how a wrong "not affected" happens. The 200,000 figure is about twice the rows I expect from a request of a few hundred items, including one package the size of the Linux kernel; it has not been measured on real data (section 13). Each item lists at most 100 advisories (Affected first, then KEV, then score), with `advisories_truncated` set. Status and counts are always computed over all of them. Each advisory lists at most 20 matched ranges. The handler runs under a 30-second context limit.

The index adds write cost to the merge's delete-and-reinsert of child rows. That has not been measured. Section 13 covers it.

## 10. Authorisation and limits

- **Role:** viewer. It reads only global CVE data. The route is org-scoped so that RBAC, the tier and the org rate limit apply.
- **Route:** `r.With(srv.RequireOrgRole(RoleViewer)).Post("/check", srv.checkComponentsHandler)`, a chi route like the other org routes, with a spec-only registration.
- **Transaction helper:** `withOrgRawTx`, because the query is built from `ecosystem.FoldedNameSQL`. `cve_*` and `feed_sync_state` have no RLS, so `withBypassTx` is unnecessary and would widen the transaction's rights. `WorkerTx` is never used from handlers.
- **Not stored or logged:** the components are a picture of what an org runs. Items are neither persisted nor logged. There is no audit entry, as for other read-only routes.
- **Scopes (AUTH-3) later:** when scopes exist, this route gains `cves:read` beside its role check, as one more entry in the `operationAccess` table and one middleware on the route. The response does not change.
- **Rate limits (AUTH-7):** `orgRateLimitMiddleware` already counts a request once regardless of its item count, which is what AUTH-7 asks for batch endpoints. A weekly run of a few hundred components is one or two requests. **Nothing in AUTH-7 has to ship with this.** The per-key bucket and `X-RateLimit-*` headers remain separate work.

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

Scores above illustrate the shape only.

**Stable values for the CLI and MCP tool:** `results` is in request order, and `index` and `id` identify each item. `advisory_id` works with `GET /cves/{id}`. `status`, `verdict`, `reason`, `evidence`, `warnings` and `error.code` are closed enumerations declared in the spec.

| Field | Values |
|---|---|
| `status` | `affected`, `not_affected`, `cannot_evaluate`, `no_advisory_found`, `invalid` |
| `verdict` | `affected`, `cannot_evaluate` |
| `reason` | `unknown_version_scheme`, `invalid_version`, `invalid_range`, `commit_ranges_only`, `no_version_bounds`, `cna_cannot_clear`, `data_incomplete`, `distro_package_not_found` |
| `evidence` | `package_range`, `nvd_cpe`, `cna` |
| `warnings` | `cna_product_not_mapped` |
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

Adding three records to the golden archive adds lines to `golden_material_hashes.json` and changes corpus counts. Existing pins must not move.

The verdict functions also get table tests for each row of sections 4.1 to 4.4 and section 7, and purl mapping gets a table test for each row of section 3.2. A break test, run once during implementation, removes the CNA-must-not-clear rule and confirms the two bold cases fail.

## 13. Measure on the first full ingest

- Share of items and advisories answering `cannot_evaluate`, by reason.
- Whether the "several fixes under one `introduced`" shape occurs outside `Root:*` and `GIT`.
- Real row counts per package, to confirm the 200,000 limit.
- Write cost of the three new indexes during a backfill.
- `cve_affected_packages_eco_pkg_idx` may become redundant.

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

| Decision | Recommendation | Alternative |
|---|---|---|
| Distro answers before DATA-3 | Ship without it, returning `advisory_id` and a `cve_id` derived where the ID states it. | Build DATA-3 first, so that `USN-*` rows also name their CVEs. Delays the endpoint for a label. |
| The acceptance example naming `php` | Change it to `php8.5`, because no feed has `php` on Ubuntu 26.04. | Keep `php` and add a name-mapping table for distro metapackages. |
| A distro name with no rows | `cannot_evaluate`, because a binary name otherwise reads as clean. | `no_advisory_found` with a warning. Less noise, but a script keyed on status misses it. |
| CNA data can never clear a version | Keep this rule. CVE-2026-56847 shows the failure. A CVE before NVD analysis stays `cannot_evaluate` after patching. | Trust `defaultStatus: unaffected`. Answers sooner and produces a wrong "not affected" on real records. |
| NVD's answer over a CNA wildcard, when NVD has that branch | Allow it, extending the batch design's third rule. Otherwise Node versions never clear. | Keep the rule strict and change the acceptance example for `24.22.1`. |
| CPE to CNA name table | A short table in code, plus a warning for unmapped products. | Caller supplies CNA names. Moves the upkeep to every caller. Or use NVD only, which loses disclosure-day answers. |
| Stale feeds count as incomplete | Yes, at 7 days without success. | Walk-finished only, as the batch design defined it, with `last_success_at` for callers to judge. |
| CPE row with `*` and no bounds | `cannot_evaluate`, as the requirement says for a missing range. | Affected, NVD's literal meaning. Never clears after patching. |
| Item cap and the candidate limit | 500 items; over 200,000 rows fails the request. | 1,000 items, or answer `cannot_evaluate` per item when over the limit. That needs a per-item read and gives up the single statement. |
| Purl parser | `packageurl-go`. | Our own parser, about 60 lines. |

Left out, and easy to add later: an item-level "lowest version that clears every advisory", which `fixed_version` per advisory lets the server compute by the section 7 method; CNA `packageName` lookups for package-form items; the CNA `packageURL` field, which the feed does not store.

## 16. Delivery

One pull request with small commits, because no part is useful alone: the migration and NVD `caught_up` field; `internal/version` additions; `internal/check` with table tests; the store read; the handler and spec; golden additions. The usual review skills apply when the code exists: `schema-review` for the migration, `security-review` for the route, `pitfall-check`, `plan-check` against `PLAN.md` §9.2. `PLAN.md` §16 and Appendix B gain the endpoint.

This design has not had an independent review.
