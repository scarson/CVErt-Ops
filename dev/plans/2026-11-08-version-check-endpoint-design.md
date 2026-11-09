# Design: the version check endpoint (MATCH-1)

Date: 2026-11-08. Author: Claude, for Sam. Status: for Sam's review. No implementation code or migration exists yet.

## 1. Goal and scope

`POST /api/v1/orgs/{org_id}/check` answers, for a list of exact component versions: which advisories affect this version, which range matched, and what version fixes it. It is for components that per-host scanners cannot see, such as Node, PHP and .NET in runner tool caches. Scripts, the planned API-client CLI (`check` command) and the planned MCP server (`check_components` tool) are its callers.

**The failure to design against is a wrong "not affected".** It tells someone to stop looking. Every rule below that has to choose picks "affected" or "cannot evaluate" over "not affected".

**Not in scope:** joining distro records to their CVE (requirement DATA-3, section 6), scoped API keys (AUTH-3), per-key rate limits (AUTH-7), a version condition in alert rules, and Windows build comparison (DATA-8).

**Evidence.** Code was read at `origin/dev` commit `bbc7440`. Upstream data was read on 2026-11-08 from `api.osv.dev`, `cveawg.mitre.org` and the NVD API, and from the golden fixtures in this repository. Query plans were measured on PostgreSQL 18 with synthetic data (section 9). **None of this has run against a full ingest of live feeds.** Section 13 lists what to measure when one exists.

The data rules come from `dev/plans/2026-11-08-cve-range-data-batch-design.md` section 9 (four rules for this endpoint). Section 4 of this document applies the third rule to data sources that design did not cover, and section 5 narrows its completeness rule for distro ecosystems.

## 2. Findings that shaped the design

| Finding | Evidence | Consequence |
|---|---|---|
| OSV names distro **source** packages. `php` on `Ubuntu:26.04:LTS` has no records; `php8.5` has four. | OSV API query for each name. | The acceptance example naming `php` cannot pass as written. See section 6. |
| Binary package names exist only in Ubuntu's `ecosystem_specific.binaries`, which is not stored. Debian records have no binary list. | OSV records for `php8.3` on Ubuntu and `curl` on Debian. | A binary name finds nothing, which would read as a clean answer unless handled (section 6). |
| Package rows for distro advisories already exist, under `UBUNTU-CVE-*`, `DEBIAN-CVE-*` and `USN-*` IDs. | The OSV adapter stores them; real records carry the correct fixed version. | The endpoint looks up by package, so it can answer without the join. |
| KEV and EPSS are written to the `CVE-*` row. A `UBUNTU-CVE-*` row is a different row, and merge resolves each row alone. | `internal/feed/kev/adapter.go`, `internal/merge/resolve.go`. The requirement lists CVE-2026-109618 and CVE-2026-109619 as in KEV. | Read from its own row, the acceptance example's Ubuntu record reports `in_cisa_kev: false` for an exploited CVE (section 6). |
| A CNA's `defaultStatus: unaffected` is not reliable. CVE-2026-56847 lists `26.5.0` with `lessThanOrEqual: 26.5.0` and default `unaffected`, while NVD records 26.0.0 to 26.5.0 as vulnerable. | CVE record and NVD API. | Read literally, Node 26.4.0 is "not affected" on a CVE that affects it. CNA data must never clear a version (section 4.3). |
| `defaultStatus: affected` is also unreliable. CVE-2024-4577 lists ranges per PHP branch with default `affected`, so a fixed version falls through to "affected". | CVE record. | The default status can neither clear nor condemn a version. |
| Multi-branch `changes[]` cannot be read literally in one direction. CVE-2024-7347 (nginx) says unaffected at 1.26.2 and 1.27.1 inside one range, so a literal reading clears 1.27.0, which is affected. CVE-2021-44228 steps to `affected` again at 2.4 and 2.13.0. | CVE record, golden MITRE archive. | A step to `affected` is trusted. A step to `unaffected` is not (section 4.3). |
| Node CNA records use `{version: "12.0", lessThan: "12.*"}` for end-of-life major lines and concrete bounds for maintained ones. The CVE specification reads `*` as infinity within the ordering, so `[1.0.0, 2.*)` holds 1.x and 2.x. | CVE-2024-27980, CVE-2025-23166, CVE-2026-21637; CVE version specification. | Wildcard upper bounds cannot be evaluated (section 4.3). Maintained Node lines are not touched by this. |
| CNA and CPE names differ for most products the endpoint is for: `nodejs:node.js` against `nodejs` / `node` and `nodejs` / `nodejs`, `php:php` against `PHP Group` / `PHP`, `f5:nginx` against `F5` / `NGINX Open Source`, `python:python` against `Python Software Foundation` / `CPython`. Spellings vary within one vendor: `.NET 6.0`, `.NET 9.0 runtime`, `nginx` / `nginx`. | CVE records (CVE-2025-27210, CVE-2026-70007, CVE-2023-21538, CVE-2017-7529) and NVD criteria. | Comparing names directly finds almost nothing, and a table cannot be proved complete (section 4.5). |
| `cve_cna_affected` holds only the highest-priority source's copy. MITRE's array replaces NVD's relay of it, even when the two differ. | `internal/merge/resolve.go`, `resolveCNAAffected`. | Evidence the corpus holds can be absent from the table (section 4.3). |
| Some CNA records name a package: `pkg:npm/fastify` on CVE-2026-107832, which no package feed in the golden data has. | Golden NVD page. 1 of 67 entries in the golden MITRE archive has `packageURL`. `ParseCNAAffected` drops the field. | A package-form lookup would miss it (section 4.6). |
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
| `cargo`, `gem`, `nuget`, `pub` | `crates.io`, `RubyGems`, `NuGet`, `Pub` | `name` |
| `hex` with no namespace | `Hex` | `name` |
| `composer` | `Packagist` | `vendor/name` |
| `deb` | from namespace and `distro` | `name` |
| `apk` | `Alpine:v<major>.<minor>` from `distro` | `name` |
| anything else, including `rpm` | refused: `unsupported_purl_type` | |

Red Hat's OSV strings carry a repository stream (`Red Hat:enterprise_linux:8::appstream`) that a purl does not hold, so `rpm` must use the `ecosystem` form.

A purl can name a package the public registry does not hold, and mapping it to the public name would answer for a different package. A `hex` namespace is a private organisation, so it is refused with `unsupported_purl_namespace`, as is a namespace on any type whose row above has none. A `repository_url` qualifier is refused with `unsupported_repository`.

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

Ubuntu Pro streams (`Ubuntu:Pro:24.04:LTS`) are not supported in purl form, as a deliberate restriction. OSV writes them as `distro=esm-infra/focal` and similar, which is refused with `distro_not_recognised`, and the `ecosystem` form names them directly. For `deb`, an `epoch` qualifier must be digits, and is prepended to the version when the version has none. Leaving it off sorts the version too low, and a range without an epoch can then wrongly clear or condemn it. A version that carries a different epoch from the qualifier is refused with `conflicting_version`. A purl with no version is refused with `version_required`. Qualifiers other than `distro`, `epoch` and `repository_url` are ignored, and a purl with a subpath is refused with `invalid_purl`.

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
| One item over its row limit (section 9) | 200. That item is `cannot_evaluate`, reason `too_many_candidates`; the others are answered. |
| Request over its row or byte limit (section 9) | 422 with `candidate_limit_exceeded`. The caller splits the request. |
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

An entry is read as an ordered list of segments. The first runs from `version` with the entry's `status`. Each `changes[]` item starts a new segment at its `at` with its `status`. The last segment ends at the upper bound. An entry with no `changes[]` is one segment.

| Version position | Result |
|---|---|
| Inside a segment with status `affected`, whatever the entry's first status | **Affected.** Fix candidate: the start of the next segment if its status is `unaffected`, otherwise `lessThan` if this is the last segment. |
| Equal to the `at` of a change to `unaffected` | No statement. |
| Inside a later `unaffected` or `unknown` segment, above its `at` | Indeterminate. A step to `unaffected` is the shape that wrongly clears nginx 1.27.0. |
| Inside the first segment, whose status is `unaffected` or `unknown` | No statement. |
| Outside the bounds | No statement. |
| Comparable lower bound at or below the version, and an upper bound that is a wildcard: below the end of the line it names, so `[1.0.0, 2.*)` runs through every 2.x | Indeterminate. Read literally this is Affected with no fix, and such records would then report a patched version as affected for good. |
| Comparable lower bound at or below the version, and an upper bound the comparator cannot read | Indeterminate. |
| No usable lower bound: `unspecified`, `n/a`, `git`, free text the grammar cannot read, a value non-numeric under `custom` | No version information. |
| `defaultStatus` of any value | No statement. |

Over all of a product's entries the strongest result wins: Affected, then Indeterminate, then No version information, then No statement. With no other source for the advisory, Affected stands and anything else is cannot evaluate, reason `cna_cannot_clear`. A CVE whose only data is a CNA record therefore answers Affected or cannot evaluate, never Not affected.

**All copies are read.** `resolveCNAAffected` changes to store the distinct entries of every source, rather than the highest-priority source's alone. CNA data can only condemn a version, so a stale copy costs at most one extra cannot-evaluate, and a newer copy is never hidden. The field is not a `material_hash` input, so no alert fires because of this. Existing rows change at the next merge of each CVE, and no backfill is needed.

### 4.4 When NVD and CNA both have data

For a CPE-form item and one advisory:

1. Affected if an NVD row or a CNA entry reports Affected.
2. Cannot evaluate if any NVD row answers cannot evaluate.
3. Cannot evaluate, reason `cna_indeterminate`, if a CNA entry is Indeterminate.
4. Not affected if NVD has at least one comparable row and all report Not affected.
5. With no NVD rows, the CNA result of section 4.3 stands.

This is the batch design's third rule, with one reading made explicit: a CNA entry with no version information is not a range, so it does not stop step 4. It says a product is affected and states no version, and NVD's rows are then the only version statement that exists. Without this reading, one old `unspecified` entry would keep a long-lived product unanswered for good.

Worked examples, real records:

| Version | NVD | CNA | Result |
|---|---|---|---|
| Node 24.22.0, CVE-2026-111497 | `[23.0.0, 24.22.1)` contains it | Names Google Brotli, not Node | Affected, fixed 24.22.1 |
| Node 24.22.1, same CVE | Outside every range | None | Not affected |
| nginx 1.27.0, CVE-2024-7347 | Marks it vulnerable | Above the first change: Indeterminate | Affected, from NVD |
| Log4j 2.14.0, CVE-2021-44228, CNA row alone | Not used | Inside the segment that steps to `affected` at 2.13.0 | Affected, fixed 2.15.0 |
| Node 12.22.12, CVE-2024-27980 | Outside every range | `12.0` to `12.*`: Indeterminate | Cannot evaluate, `cna_indeterminate` |
| Node 26.4.0, CVE-2026-56847 | `[26.0.0, 26.5.0]` contains it | No statement | Affected, no fix claimed (the upper bound is inclusive) |
| Same, before NVD analyses it | None | No statement | Cannot evaluate, `cna_cannot_clear` |

### 4.5 Finding CNA rows for a CPE

The CPE's own vendor and product (with `_` read as a space) are always looked up, which finds `openssl:openssl` and `nginx:nginx`. A small table in code adds further CNA names, compared in lower case. It is seeded with the products this endpoint exists for, from the real records in section 2. A product name can be exact or a prefix.

| CPE | CNA vendor and product | Name fragment |
|---|---|---|
| `nodejs:node.js` | `nodejs` / `node`, `nodejs` / `nodejs` | `node` |
| `php:php` | `php group` / `php` | `php` |
| `f5:nginx`, `nginx:nginx` | `f5` / `nginx open source`, `f5` / `nginx` | `nginx` |
| `microsoft:.net`, `microsoft:.net_core` | `microsoft` / prefix `.net ` (so `.NET 6.0`, `.NET 9.0 runtime` and later majors) | `.net` |
| `postgresql:postgresql` | `n/a` / `postgresql` | `postgresql` |
| `python:python` | `python software foundation` / `cpython` | `python` |

**A product with no CNA name cannot be cleared.** With no table entry and no direct match, a CVE NVD has not analysed cannot be seen at all. An answer that would be `not_affected` becomes `cannot_evaluate`, reason `cna_product_not_mapped` (section 4.7), and `no_advisory_found` carries the same name as a warning. A status-keyed script would miss a warning, which is the reason a distro lookup with no rows is not `no_advisory_found` either.

**A table cannot be proved complete, so nearby names block too.** Each product has a vendor and a name fragment: the table's, or for a direct match the CPE's own. A CNA row under that vendor whose product contains the fragment, on a CVE with no `cve_cpe_matches` row at all, and which the lookups above did not use, makes that CVE an advisory answering cannot evaluate, reason `cna_name_uncertain`. Its versions are not compared, because the product is not known to be this one. This lasts only until NVD analyses the CVE. `Microsoft .NET Framework 4.8` will hold back a .NET check during that window, which is accepted.

**What remains unseen.** A CVE that NVD has not analysed and whose CNA record uses another vendor spelling, or a product name without the fragment, or no product at all. `not_affected` therefore means "not in any analysed or CNA-named advisory we hold". The API description says so, and no flag can close this gap.

### 4.6 CNA rows for package items

`cve_cna_affected` gains `package_key`, computed by `ParseCNAAffected` from `packageURL`: `<type>/<namespace>/<name>` in lower case, with `_` and `.` folded to `-` for `pypi`. A package item looks up the key for its ecosystem and name, and matching rows are read by section 4.3. Section 4.4 applies with the package rows in place of NVD's. So `npm` / `fastify` `5.12.3` answers Affected with fix `5.12.6` from the CNA alone. `packageName` and `collectionURL` are not used, because they need a table of registry URLs.

Distro items do not use this: the CNA describes the upstream package, not the distro's build of it.

### 4.7 Item status

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

Cursors, candidate rows, statuses and enrichment are all read in one `REPEATABLE READ`, read-only snapshot. Reading them under the default `READ COMMITTED` would let a merge that commits between two statements combine old NVD rows with new CNA rows, and that mixture can clear a version neither committed state cleared.

"Complete" means the walk finished. It does not mean every record parsed, because adapters log and skip unreadable records.

## 6. Distro answers without DATA-3

**Recommendation: ship without DATA-3.** The endpoint looks up by package, and the package rows already exist under each distro advisory's own ID. Real data for the acceptance example:

```
Ubuntu:26.04:LTS / php8.5, version 8.5.4-0ubuntu1.4
  UBUNTU-CVE-2026-109618  fixed 8.5.4-0ubuntu1.5
  UBUNTU-CVE-2026-109619  fixed 8.5.4-0ubuntu1.5
  USN-8948-1              fixed 8.5.4-0ubuntu1.5
```

The response returns `advisory_id` (the stored record, usable with `GET /cves/{id}`) and `cve_ids`, an array because one record can cover several CVEs. `cve_ids` holds `advisory_id` for a `CVE-` record, the ID's own CVE for `UBUNTU-CVE-*`, `DEBIAN-CVE-*` and `ALPINE-CVE-*` (each covers one CVE by construction; 259 of 259 real Debian and Ubuntu records checked agree with their `upstream` field, and a sample of Alpine IDs was checked in review), and is empty for `USN-*` and `DSA-*` until DATA-3 fills it, with no change to the response shape.

**Exploit data comes from the CVE, not the distro record.** `in_cisa_kev` and `epss_score` belong to the `CVE-*` row (section 2), so a read by the `cve_ids` values fills them in, in the same snapshot, and sorting uses them. Over several CVEs, `in_cisa_kev` is true if any is, and `epss_score` is the highest. Where `cve_ids` is empty, both are `null`, which means "not known", never false. `severity` and the CVSS scores stay those of the distro's own record, as the requirement for DATA-3 notes that distro records carry their own. An upstream CVE that was rejected does not remove the distro advisory: the distro record still states a fix, and leaving it fails towards "affected".

Counts are of advisory records. `USN-8948-1` and `UBUNTU-CVE-2026-109618` count as two, because without DATA-3 the server cannot say that the USN contains that CVE. The API description says "records", not "vulnerabilities".

DATA-3 would be needed first only if the endpoint had to start from a CVE ID, or had to map binary names. An agent asking "what fixes CVE-X on Ubuntu 26.04" calls this endpoint with the package and version, and reads the advisory whose `cve_ids` holds CVE-X. That needs the package name; DATA-3 would let it start from the CVE alone. Binary names are handled below.

**The acceptance example must change.** The requirement says `php` `8.5.4-0ubuntu1.4`. `php` is not a source package on Ubuntu 26.04, so no feed has it. The example that can pass names `php8.5`. Sam needs to accept this (section 15).

**Binary names.** A caller with `dpkg-query` output has names like `php8.5-cli`, and a Debian or Ubuntu lookup with such a name finds nothing. Reporting `no_advisory_found` would read as clean to a script. So a zero-row lookup in a distro ecosystem answers `cannot_evaluate` with reason `distro_package_not_found`, and the description says to use the source package name. This also marks a real source package with no advisories as unanswered. That cost is small, because per-host distro matching stays with Trivy and few distro items will reach this endpoint.

## 7. Fix reporting

`fixed_version` is computed per advisory:

1. Candidates are the upper bounds of the ranges that report Affected for this version: package `fixed`, NVD `versionEndExcluding`, CNA `lessThan` or the start of the following `unaffected` segment. A `last_affected` bound is not a candidate, because it does not say what fixes the problem.
2. Candidates are ordered by one comparator: the ecosystem's for a package item, `CheckNumeric` for a CPE item. If any candidate cannot be read by it, such as a Python `1.1rc1` beside numeric bounds, no minimum can be established and `fixed_version` is `null`.
3. Take the lowest candidate that no range of the advisory reports as Affected or cannot evaluate, and that no CNA entry reports as Affected or Indeterminate under section 4.3.
4. If no candidate passes, `fixed_version` is `null`.

Only ranges that contain the version contribute, so a Node 24.22.0 lookup considers `24.22.1` and never `22.23.4`. When two sources disagree (fixed in 1.2.3 and in 1.2.4), both ranges contain 1.2.0, 1.2.3 is still inside the second, and 1.2.4 is returned.

**Same branch.** MATCH-1 asks for the fix on the same branch. A range with no lower bound cannot show that: Node 20.0.0 inside `(, 22.23.4)` gets `22.23.4`. That version is outside the range, so it does clear the advisory, and an empty answer would hide the only upgrade the record names. So `fixed_version` is kept and `fix_branch` qualifies it: `same` when the range has a stated lower bound above zero or the version and the fix share their leading number, and `unconfirmed` otherwise. A caller that needs the requirement's strict meaning reads only `same`.

`fixed_version` means "the lowest version the advisory data no longer reports as affected". For 460 GHSA ranges of the form `< B` with no patch, a release at B may not exist. The stored row cannot tell those apart, so the API description uses this wording rather than promising a published fix.

## 8. Retracted records

A row joins to `cves`, and an advisory with `COALESCE(lower(cves.status), '') IN ('rejected', 'withdrawn')` is excluded from verdicts, the same test the alert paths use. This covers MITRE and NVD rejections in any case, and tombstones from a CVE whose every source row is withdrawn. A withdrawn advisory among live ones already contributes no rows (batch design section 5.3).

Excluded advisories whose rows still exist are counted in `counts.retracted`, so a caller can see that one existed. A withdrawn OSV or GHSA advisory has had its rows deleted by merge, so it cannot be found by package and is not counted. An item whose only advisories are retracted is `no_advisory_found`, in distro ecosystems too: the rows prove the package name exists, which is what `distro_package_not_found` is there to question.

## 9. Performance

One SQL statement per data source (packages, CPE rows, CNA names, CNA package keys, and CNA rows near a name), each joining `unnest` of the distinct keys in the request to its table and to `cves`, all inside the snapshot of section 5. Identical items are looked up once.

**Indexes (next free migration number, `CONCURRENTLY`, no-transaction):**

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_packages_check_idx
    ON cve_affected_packages (ecosystem,
        (CASE WHEN ecosystem = 'PyPI' THEN regexp_replace(lower(package_name), '[-_.]+', '-', 'g') ELSE lower(package_name) END));
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cpe_matches_check_idx
    ON cve_cpe_matches ((cpe_normalized COLLATE "C"));
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cna_affected_check_idx
    ON cve_cna_affected ((left(lower(vendor), 256) COLLATE "C"), (left(lower(product), 256) COLLATE "C"));
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cna_affected_package_key_idx
    ON cve_cna_affected (package_key) WHERE package_key IS NOT NULL;
```

- The package expression is `ecosystem.FoldedNameSQL`'s output, and the query is built from that function, so the two cannot drift. A test asserts the index definition matches.
- CPE rows are found by a range on the prefix, with the collation written on both comparisons: `m.cpe_normalized COLLATE "C" >= k.lo COLLATE "C" AND m.cpe_normalized COLLATE "C" < k.hi COLLATE "C"`, for `lo = 'cpe:2.3:a:nodejs:node.js:'` and `hi = 'cpe:2.3:a:nodejs:node.js;'`. Without it, on a database that is not C-collated, the index is not used. `LIKE` with array parameters cannot use a btree. Taking the prefix as written also means escaped colons need no special handling.
- CNA rows are found by `left(lower(vendor), 256) COLLATE "C" = k.v COLLATE "C"` and a range on `left(lower(product), 256) COLLATE "C"`. A prefix row uses its prefix bounds. An exact name uses `[name, name || chr(1))`, then a recheck of the whole value in the same statement, because the index holds only 256 characters. `lower(vendor)` alone does not use this index.
- CNA `vendor` and `product` can each reach 2,048 characters, and a value over the btree row limit would fail the merge of that whole CVE. `left(..., 256)` keeps the key under the limit. The migration comment on `cve_cna_affected` already records this hazard.
- `cve_cna_affected` gains a nullable `package_key text` (section 4.6). The next merge of each CVE fills it.

**Measured**, PostgreSQL 18, 700,000 `cves`, 6 million package rows, 3 million CPE rows, 420,000 CNA rows, one package with 40,000 rows:

| Lookup | Keys | Rows | Today's indexes | With index |
|---|---:|---:|---|---|
| Packages | 300 | 58,423 | 10.9 s, parallel sequential scan and external sort | 0.25 to 0.41 s, one index scan per key |
| CPE | 100 | 8,836 | 13.8 s, join filter over 2.75 million rows | 0.72 s |
| CNA, exact names | 100 | 1,244 | 278 ms | 4 ms |
| CNA, exact and prefix, a 200,000-row vendor, not C-collated | 100 | 101,029 | not measured | 0.44 to 0.55 s |
| CNA rows near a name, on CVEs with no NVD rows | 3 | 2,173 | not measured | 117 ms |

The plan was the same with a generic plan as with a custom plan. These were synthetic rows. The row counts are estimates of a full corpus, and the shape of real name distributions may differ.

Version comparison costs 5.2 µs for dpkg and 2.3 µs for numeric on the development machine, so 58,000 rows take about 0.3 s, before fix candidates are checked.

**Bounds.** Each statement reads each key through `CROSS JOIN LATERAL (... LIMIT 50001)`, still one statement per data source, with the key's position returned so rows can be attributed. The key limit stops one key from flooding memory. Measured on the same synthetic data with 300 keys, one holding 90,000 rows: 110,951 rows in 0.7 to 1.6 s, one index scan per key under a `Limit`, the same plan generic and custom, and only that key at the limit.

The limits a caller sees are counted in Go as rows arrive, because no single statement sees them all:

| Limit | Counted over | When passed |
|---|---|---|
| 50,000 rows for one item | All sources and name variants that item uses, including a key that reached its limit | That item is `cannot_evaluate`, `too_many_candidates`; the others are answered |
| 200,000 rows for one request | Every statement | Reading stops; 422 `candidate_limit_exceeded` |
| 128 MiB of row data for one request | Every statement, including each CNA row's variable `versions` array | Same 422 |
| 1,000 ranges for one component in one advisory | Rows for that advisory | That advisory is `cannot_evaluate`, `too_many_ranges` |

A partial read cannot say which items lost rows, and a truncated read is exactly how a wrong "not affected" happens, so nothing is answered from one. The 200,000 figure is about twice the rows I expect from a request of a few hundred items, including one package the size of the Linux kernel; none of these limits has been measured on real data (section 13).

Rows are read into memory, the transaction ends, and only then are versions compared, so no database connection is held for the comparison work. Fix validation (section 7) stops at the first candidate that passes, and the range limit keeps its worst case at about a million comparisons per advisory. The comparison loop checks the 30-second context between advisories, because a context cannot interrupt pure computation. A process runs at most 4 checks at once, by the semaphore pattern `argon2Sem` uses, and a request that finds none free gets 503 with `Retry-After`. Each item lists at most 100 advisories (Affected first, then KEV, then score), with `advisories_truncated` set. Status and counts are always computed over all of them. Each advisory lists at most 20 matched ranges. The handler runs under a 30-second context limit.

The index adds write cost to the merge's delete-and-reinsert of child rows. That has not been measured. Section 13 covers it.

## 10. Authorisation and limits

- **Role:** viewer. It reads only global CVE data. The route is org-scoped so that RBAC, the tier and the org rate limit apply.
- **Route:** `r.With(srv.RequireOrgRole(RoleViewer)).Post("/check", srv.checkComponentsHandler)`, a chi route like the other org routes, with a spec-only registration.
- **Transaction helper:** the behaviour of `withOrgRawTx`, because the query is built from `ecosystem.FoldedNameSQL`, with `sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}` passed to `BeginTx` (section 5). The helper gains that option rather than being copied. `cve_*` and `feed_sync_state` have no RLS, so `withBypassTx` is unnecessary and would widen the transaction's rights. `WorkerTx` is never used from handlers.
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
          "cve_ids": ["CVE-2026-111497"],
          "verdict": "affected",
          "reason": null,
          "fixed_version": "24.22.1",
          "fix_branch": "same",
          "matched_ranges": [
            {"evidence": "nvd_cpe", "cpe": "cpe:2.3:a:nodejs:node.js:*:*:*:*:-:*:*:*", "introduced": "23.0.0", "fixed": "24.22.1"}
          ],
          "matched_ranges_total": 1,
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

Scores above illustrate the shape only. `in_cisa_kev` and `epss_score` are nullable: `null` means the record names no CVE to read them from (section 6).

**Stable values for the CLI and MCP tool:** `results` is in request order, and `index` and `id` identify each item. `advisory_id` works with `GET /cves/{id}`. `status`, `verdict`, `reason`, `evidence`, `warnings` and `error.code` are closed enumerations declared in the spec.

| Field | Values |
|---|---|
| `status` | `affected`, `not_affected`, `cannot_evaluate`, `no_advisory_found`, `invalid` |
| `verdict` | `affected`, `cannot_evaluate` |
| `reason` | `unknown_version_scheme`, `invalid_version`, `invalid_range`, `commit_ranges_only`, `no_version_bounds`, `cna_cannot_clear`, `cna_indeterminate`, `cna_name_uncertain`, `cna_product_not_mapped`, `data_incomplete`, `distro_package_not_found`, `too_many_candidates`, `too_many_ranges` |
| `evidence` | `package_range`, `nvd_cpe`, `cna` |
| `fix_branch` | `same`, `unconfirmed`, or `null` when `fixed_version` is `null` |
| `warnings` | `cna_product_not_mapped` |
| `error.code` | `invalid_form` (not exactly one of the three forms), `invalid_ecosystem`, `ecosystem_release_required`, `invalid_purl`, `unsupported_purl_type`, `unsupported_purl_namespace`, `unsupported_repository`, `distro_required`, `distro_not_recognised`, `conflicting_distro`, `invalid_cpe`, `version_required`, `conflicting_version`, `value_too_long` |

`matched_ranges` is capped at 20; `matched_ranges_total` says how many there were. Verdicts and fixes use all of them.
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
| Distro | `Ubuntu:26.04:LTS` / `php8.5`, `8.5.4-0ubuntu1.4` | The two CVEs, fixed `8.5.4-0ubuntu1.5`; USN with `cve_ids` empty | Three real OSV records added to the golden archive |
| Distro, fixed | same, `8.5.4-0ubuntu1.5` | `not_affected` | Same |
| Distro, wrong name | `php`, then `php8.5-cli` | `cannot_evaluate`, `distro_package_not_found` | Same |
| Multi-branch package | `Packagist` / `drupal/core`, on one branch | Fix from that branch | `SeedCorpus` (`DRUPAL-CORE-2018-002`) |
| Retracted | Package or CPE of a rejected or withdrawn record | Excluded, `counts.retracted` | `SeedCorpus` where a rejected or withdrawn golden record keeps rows; otherwise a targeted patch |
| No comparator | The `Root:*` ecosystem, package and a version from `ROOT-OS-DEBIAN-12-CVE-2025-40110` | `cannot_evaluate`, `unknown_version_scheme` | `SeedCorpus` |
| CNA only | CPE `fastify:fastify`, `5.12.3` and `5.12.6` (`CVE-2026-107832`, not yet analysed by NVD) | Affected, fixed `5.12.6`; then `cannot_evaluate`, never Not affected | `SeedCorpus` |
| **CNA must not clear** | CVE-2026-56847 with NVD rows removed, `26.4.0` | `cannot_evaluate` | Targeted patch, real CNA values |
| **`changes[]` must not clear** | CVE-2024-7347, `1.27.0`, no NVD rows | `cannot_evaluate` | Targeted patch, real CNA values |
| Wildcard blocks NVD's answer | Node CNA `12.0` to `12.*`, NVD rows all Not affected, `12.22.12` | `cannot_evaluate`, `cna_indeterminate` | Targeted patch |
| Wildcard runs to the end of its line | CNA `[1.0.0, 2.*)`, `1.5.0` and `3.0.0` | `cannot_evaluate`; then no statement | Targeted patch |
| A step to `affected` is kept | CVE-2021-44228 values, `2.14.0`; and an entry first `unaffected` with a step to `affected` | Affected | Targeted patch, real CNA values |
| Entry with no version information | CNA `unspecified`, NVD all Not affected | `not_affected` | Targeted patch |
| Mixed snapshot | A merge commits between two reads | Both reads see one state | Concurrent test on the snapshot helper |
| Copies disagree | MITRE CNA `[1,2)`, NVD relay `[1,3)`, NVD CPE `[1,2)`, `2.5` | Affected | Targeted patch |
| Name the table lacks | `Microsoft` / `.NET 9.0 runtime`, `9.0.20`, NVD not analysed (CVE-2026-70007) | Affected, by the prefix row | Targeted patch, real CNA values |
| Nearby name | `Microsoft` / `.NET Framework 4.8` on a CVE with no NVD rows, `.net` CPE | Advisory `cannot_evaluate`, `cna_name_uncertain` | Targeted patch |
| CNA package identity | `npm` / `fastify`, `5.12.3` and `5.12.6` | Affected, fixed `5.12.6`; then `cannot_evaluate` | `SeedCorpus` |
| Private namespace | `pkg:hex/acme/foo@2.3.0` | `invalid`, `unsupported_purl_namespace` | None |
| Conflicting epochs | `pkg:deb/debian/foo@2:1.0?distro=debian-13&epoch=1` | `invalid`, `conflicting_version` | None |
| Retracted, distro | Distro package whose only record is rejected and keeps rows | `no_advisory_found` | Targeted patch |
| Fix with no same-branch evidence | Node `20.0.0` against `(, 22.23.4)` | Fixed `22.23.4`, `fix_branch: unconfirmed` | `SeedCorpus` |
| Candidates a comparator cannot order | CNA Python `1.1rc1` beside numeric bounds | `fixed_version` null | Targeted patch |
| `GIT` only | Hand-built patch | `cannot_evaluate`, `commit_ranges_only` | Targeted patch |
| `v` prefix | CPE `nodejs:node.js`, `v24.22.0` | Same as `24.22.0`; `component.version` is `24.22.0` | `SeedCorpus` |
| Exploit data on a distro record | `php8.5` example, with KEV and EPSS on the `CVE-2026-*` rows | `UBUNTU-CVE-*` shows `in_cisa_kev: true`; USN shows `null` | Same three records plus a targeted KEV patch |
| Product with no CNA name | CPE with NVD rows, all Not affected, no table entry, no direct CNA rows | `cannot_evaluate`, `cna_product_not_mapped` | Targeted patch |
| Item limit across sources | CPE item whose CPE and CNA rows together pass the limit, neither alone | `cannot_evaluate`, `too_many_candidates` | Targeted patch, limit lowered by the test |
| Distro depends only on OSV | OSV cursor set, GHSA cursor absent, distro item | `data_complete: true` | `UpsertFeedSyncState` |
| Per-item limit | One package over the limit, one normal item, limit lowered by the test | First `cannot_evaluate`, `too_many_candidates`; second answered | Targeted patch |

Adding three records to the golden archive adds lines to `golden_material_hashes.json` and changes corpus counts. Existing pins must not move.

The verdict functions also get table tests for each row of sections 4.1 to 4.7 and section 7, and purl mapping gets a table test for each row of section 3.2. A break test, run once during implementation, removes the CNA-must-not-clear rule and confirms the two bold cases fail.

## 13. Measure on the first full ingest

- **Go/no-go before the CLI and MCP tools are built on `status`:** the share of items answering `cannot_evaluate`, and of advisories, by reason, and per product for Node, PHP, .NET, nginx, OpenSSL and PostgreSQL. An item is `cannot_evaluate` when any one advisory is. For a long-lived product, one old CVE with a bare `*` row, or one NVD has not analysed, can hold the item there for good, and then "not affected" would be rare in exactly the cases this endpoint is for. The per-advisory verdicts and `counts` still carry the detail. If the rate is high, the roll-up changes before those consumers exist.
- Whether the "several fixes under one `introduced`" shape occurs outside `Root:*` and `GIT`.
- Real row counts per package, to confirm the 50,000 and 200,000 limits.
- Write cost of the three new indexes during a backfill.
- `cve_affected_packages_eco_pkg_idx` may become redundant.
- How often a looser CNA rule would be wrong: for CVEs with one product on each side and NVD analysis, how often NVD reports a version at or past the CNA's highest clean bound. The golden data is too small to decide this (section 15).
- Share of CPE lookups blocked by a vulnerable row with no version bounds. In the golden NVD page, 11 of 503 vulnerable rows have `*` and no bounds.
- How many CPE items answer `cna_product_not_mapped` or `cna_name_uncertain`, and for which names. Those are the table rows worth adding.
- How many CVEs carry `packageURL` and have no GHSA or OSV row.

This run happens during implementation, and also confirms the query plans in section 9 on the real corpus.

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
| Distro answers before DATA-3 | Ship without it. Return `advisory_id`, `cve_ids` derived where the ID states it, and exploit data read from those CVEs. | Build DATA-3 first. Or parse only OSV's `upstream` field now. | A `USN-*` record has no CVE, so no KEV signal. One vulnerability counts as two records. An agent cannot start from a CVE ID. Reading `upstream` alone would fix the USN gap with far less than all of DATA-3. | These cost ranking and labels, not verdicts. The same fix appears on the `UBUNTU-CVE-*` record, which does carry its CVE. `upstream` still needs the join designed (DATA-3 itself notes "related" may be right, not "same record"). `cve_ids` takes that data later with no change to the response. |
| The acceptance example naming `php` | Change it to `php8.5`. | Keep `php` and add a table of distro metapackages. | The requirement is the contract, and `php` is the name a person would type. | The version in the example belongs to `php8.5`. As far as I know the binary `php` comes from `php-defaults` with its own numbering (general knowledge, not checked), so a table would compare a version against the wrong package, and needs upkeep per release. |
| A distro name with no rows | `cannot_evaluate`. | `no_advisory_found` with a warning. | A real source package with no advisories is common. Marking it unanswered teaches people to ignore the status, and `no_advisory_found` is already documented as "nothing known". | `dpkg-query` output is binary names in bulk, and a script branches on status. The reason is distinct, so a script can treat it separately. Few distro items are expected here. |
| CNA data can never clear a version | Keep this rule, while keeping every segment that says `affected`. A CVE before NVD analysis stays `cannot_evaluate` after patching. | Trust `defaultStatus: unaffected`. Or clear a version above the highest clean `lessThan`. | NVD's backlog can leave a patched version unanswered for weeks, at the moment someone wants to confirm a patch. Clean bounds are probably right most of the time. | Of the 3 golden records with clean CNA bounds, one product and NVD analysis, one (CVE-2026-56847) would be wrongly cleared. That sample is tiny, so section 13 measures it on a full ingest. The rule can loosen later with data. A wrong clearance cannot be taken back. |
| An indeterminate CNA entry when NVD says Not affected | Cannot evaluate: the batch design's third rule as written. | Let NVD's answer stand when NVD has a bound on that branch. | One old wildcard entry can keep a version unanswered for good, and an NVD bound on the branch is a specific statement. | Both reviewers constructed clean answers from this exception, and its stated need was wrong: maintained Node lines have concrete bounds, and the acceptance CVE's CNA names Brotli. Section 13 measures the cost. |
| A CNA entry with no version information when NVD says Not affected | Does not block: NVD's rows are the only version statement. | Block, reading the third rule strictly. | The entry does say the product is affected, and the rule says anything unresolved blocks. | The entry is not a range and says nothing about this version. Blocking would keep a long-lived product unanswered for good over one `unspecified` entry, with no way to resolve it. |
| Which copy of the CNA record is used | All of them: `resolveCNAAffected` stores the union. | Keep the highest-priority source. Or read `cve_sources` during checks. | MITRE holds the CNA's own record, so a union can include a stale NVD relay, and the CVE page shows both. | CNA data only condemns, so a stale copy costs one extra cannot-evaluate, while a hidden newer copy can cause a wrong clearance. Reading `cve_sources` during checks is far more work per row. |
| CPE to CNA names | Direct name always, plus a table in code with prefixes. | Caller supplies CNA names. Or NVD only. Or derive the table from CVEs that have both. | A hand table covers only what someone added. Deriving it from co-occurrence would cover the long tail with no upkeep. | A wrong derived pair applies another product's ranges and reports false Affected. Callers should not need CNA spellings. NVD only loses disclosure-day answers. Derivation can be added later behind the same lookup. |
| CNA spellings the table lacks | A row under the vendor containing the name fragment, on a CVE with no NVD rows, blocks that CVE: `cna_name_uncertain`. | Accept the gap and document it. Or treat a product as cannot-clear unless its whole table is proved complete. | One more lookup, and `.NET Framework` holds back a .NET check. The fragment catches only spellings near the known one. | CVE-2026-70007 is a real case the first table missed. The block lasts only until NVD analyses the CVE. Proving a table complete is not possible. |
| A CPE product with no CNA name | Cannot be cleared: `cannot_evaluate`, `cna_product_not_mapped`. | Answer `not_affected` with a warning. | Products NVD has analysed thoroughly answer `cannot_evaluate` until someone adds a row, and the warning is machine-readable. | A CVE NVD has not analysed is invisible for that product, so `not_affected` would be the wrong answer this design exists to avoid. A status-keyed script misses a warning. |
| CNA package identity for package items | Store `package_key` from `packageURL` and use it. | Leave it out and measure on a full ingest. | One column, one index and one more statement for 1 of 67 golden entries. GHSA usually arrives within days. | CVE-2026-107832 shows the CPE form Affected and the package form clean for the same held record. The verdict code is reused. |
| The fix for a range with no lower bound | Keep `fixed_version`, and add `fix_branch: unconfirmed`. | `null`, the requirement's strict meaning. Or amend the requirement. | The requirement says "on the same branch", and a caller reading only `fixed_version` can be told to cross major lines. | The record's bound does clear the advisory, and it is often the only upgrade named: `null` would hide `4.17.21` from a lodash 3.x user. A strict caller reads `same` only. This needs Sam's acceptance as a qualification of the requirement. |
| Read isolation | One `REPEATABLE READ`, read-only snapshot. | Default `READ COMMITTED`, accepting a rare race. | The race needs a merge to commit between two statements on the same CVE, and adds a helper option. | Both reviewers reproduced the mixed read, and it produces a clean answer neither committed state gives. The option is one argument to `BeginTx`. |
| Package items in distro ecosystems depend on OSV only | Yes, narrowing the batch design's two-feed rule. | Keep both feeds. | One rule for all package items is simpler. | GHSA has no distro records, so waiting for it adds nothing and a missing GHSA token would block every distro answer. |
| Stale feeds count as incomplete | Yes, at 7 days without success. | Walk-finished only, with `last_success_at` for callers to judge. | An upstream outage of a week turns every clean answer into `cannot_evaluate` when probably nothing changed, and the caller already has the timestamp. | Seven days is longer than ordinary outages. A status-keyed script gets an honest answer without reading timestamps. The threshold is one constant. |
| CPE row with `*` and no bounds | `cannot_evaluate`, as the requirement says for a missing range. | Affected, NVD's literal meaning. | NVD does say every version, and this design prefers "affected" when it has to choose. | The requirement names a missing range as cannot evaluate. Affected never clears after patching, so it is a permanent alarm no one can act on. `cannot_evaluate` does not clear either. |
| Item cap and limits | 500 items. Limits per item, per request and per advisory, counted across sources (section 9). | 1,000 items. Or total limit only. Or a continuation token for partial reads. | A host SBOM has thousands of components, so a client must split. A total limit alone is simpler. | The requirement sizes a run at a few hundred components, and the CLI can split. Without the per-item limit, one package larger than the total limit could never be answered and would fail every request that names it. A continuation token needs a stable snapshot across requests. Each limit is one constant. |
| Concurrent checks | 4 per process, by the `argon2Sem` pattern; beyond that 503. | Rely on the org rate limit. Or admit requests by weight, per org. | A self-hosted single-tenant install rarely runs two checks at once, so this is code for a future problem. Weighted admission would be fairer in a shared install. | A request counts once against the rate limit whatever it costs, and can hold 128 MiB of row data. The pattern exists and is about ten lines. Four is a starting value, and fairness per org can follow if SaaS needs it. |
| Purl parser | `packageurl-go`. | Our own parser, about 60 lines. | This is a security product and we use a small part of the library. Its normalisation can change under us. | Percent-decoding and per-type rules are where hand-written parsers go wrong. It has no transitive dependencies. A table test for each mapped type shows any behaviour change on upgrade. |

**Checked and left as they are:** failing the whole request for one bad item (simpler for a client, but this route is read-only and one typo should not cost 499 answers); an org-scoped route for global data (a global route would escape RBAC, the tier and the org rate limit); listing Not-affected advisories as proof (the requirement says such an advisory "returns nothing", and counts report them).

Left out, and easy to add later: an item-level "lowest version that clears every advisory", which `fixed_version` per advisory lets the server compute by the section 7 method; CNA `packageName` lookups for package-form items; the CNA `packageURL` field, which the feed does not store.

## 16. Delivery

One pull request with small commits, because no part is useful alone: the migration, `package_key` and the union of CNA copies; the NVD `caught_up` field; `internal/version` additions; `internal/check` with table tests; the store read and its snapshot option; the handler and spec; golden additions. The usual review skills apply when the code exists: `schema-review` for the migration, `security-review` for the route, `pitfall-check`, `plan-check` against `PLAN.md` §9.2. `PLAN.md` §16 and Appendix B gain the endpoint.

The review of the implementation plan must cover the verdict tables in sections 4.1 to 4.7 explicitly. The live feed run in section 13 happens during implementation.

**Not delivered here:** the `cves:read` scope (AUTH-3), and AUTH-7's per-key bucket and headers, as section 10 says. The requirements document's `php` example needs the same edit as section 6.

**Review.** Two independent reviews of this design ran on 2026-11-09, with Codex on `gpt-6.1-sol` and `gpt-6-astra` at `xhigh`. The verdict rules in sections 4.3 to 4.7, the snapshot rule in section 5 and the limits in section 9 were rewritten from their findings.
