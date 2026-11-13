# Proposal: unfixed Red Hat package states for the version check

**Status:** proposed 2026-11-13, for Sam's decision. Option A (section 2) was built on 2026-11-13 at Sam's decision. Option B is not built.

**Context:** the version check endpoint (design: `dev/plans/2026-11-08-version-check-endpoint-design.md`; section 6, "Distros whose feeds list fixes only", records the gap this proposal addresses). For Red Hat, AlmaLinux, Rocky Linux, Alpine, SUSE and openSUSE, the stored package rows list issued fixes only, so the data cannot show a package that the distribution reports affected and has not fixed. For those distros, a clean result only means "no published fix is missing". This proposal asks whether Red Hat's own per-package states can fill the gap for RHEL, so that a RHEL item can earn `not_affected`.

All figures below come from read-only queries on the kept full ingest (`cvert_ops`, 2026-11-13).

## 1. What the data holds

**OSV Red Hat rows: fixes only, binary names, under RHSA IDs.**
- 923 `Red Hat:` ecosystems. Each names a product and, for RHEL 9 and earlier, a repository: `Red Hat:enterprise_linux:9::baseos`, `::appstream`, `::crb` and 8 others for RHEL 9. RHEL 10 is named per minor release (`Red Hat:enterprise_linux:10.2`), with no repository.
- Each record is an RHSA erratum, stored under its own ID (`RHSA-2026:77396`), with `introduced: 0` and a `fixed` NEVRA such as `1:3.5.8-2.el9_8`. None of the 636,727 rows is unfixed.
- Package names are binary RPMs: `openssl-libs`, `openssl-debuginfo`, `kernel-core`, `kernel-modules-extra`.

**The Red Hat Security Data API (`internal/feed/redhat`): per-package states, source names.**
- The adapter already fetches each CVE's `package_state[]` and `affected_release[]`. It keeps them only as vendor enrichment (`cve_vendor_enrichment.enrichment`) plus a worst-case `vendor_fix_state`. The check does not read them.
- `package_state` holds 470,811 entries. By `fix_state`:

  | State | Entries | CVEs |
  |---|---|---|
  | Not affected | 230,327 | 36,889 |
  | Fix deferred | 109,949 | 12,907 |
  | Affected | 50,988 | 10,500 |
  | Out of support scope | 36,048 | 15,367 |
  | Will not fix | 34,012 | 10,726 |
  | Under investigation | 9,487 | 1,065 |

  `Out of support scope` is not in the adapter's `fixStatePriority` table. It is currently ranked as the worst state, which is accidental but harmless.
- Each entry names a product by CPE at major-release level, with no repository: `cpe:/a:redhat:enterprise_linux:9`, and also `cpe:/o:redhat:enterprise_linux:9`, `cpe:/o:redhat:rhel_els:7`, OpenShift, Ansible and other layered products.
- Each entry names a source package: `kernel`, `openssl`, `raptor2`. Of the entries, 163,715 are containers or modules (a name with `/`), 6,941 are module streams (a name with `:`), and 307,076 are plain names.
- For RHEL 8, 9 and 10 with plain names, the unfixed states (Affected, Fix deferred, Will not fix, Out of support scope) cover about 46,000 entries, and Under investigation about 770.
- `affected_release[]` lists each fix with its advisory and source NEVRA (`openssl-1:3.5.8-2.el9_8`, `RHSA-2026:77396`).

**The names on the two sides differ.** Of the 517 source names with an unfixed RHEL 9 state, only 288 also occur as a binary name in a RHEL 9 OSV row. They match where a binary has its source's name (`openssl`, `kernel`). A caller with `rpm -qa` output has binary names. So `kernel-core` would never meet an unfixed `kernel` state unless something maps it.

**A binary-to-source map can be derived from data already held.** Join each OSV row (RHSA ID, binary name, `fixed`) to the `affected_release` entry with the same advisory and NEVRA. For RHEL 9:
- 4,410 of 4,885 binary names (90%) map to exactly one source (`kernel-core` to `kernel`, `openssl-libs` to `openssl`, `python3-libs` to `python3.9`).
- 75 map to several sources, where one advisory fixed several sources at the same NEVRA (`golang` and `go-toolset`; the `gstreamer1-plugins-*` set).
- 400 do not map. Part of that is the incomplete Red Hat feed (next point).

**The kept ingest's Red Hat feed was incomplete when these counts were taken.** Its worker had stopped at list page 645 (64,134 CVEs), on a reference URL too long for the btree index (`cve_references_cve_url_uq`), which migration 000060 (reference URL digest) fixes. So the counts above are lower bounds. On 2026-11-13 the kept ingest's worker was moved to a build of `dev`, and the feed resumed past that CVE. The adapter's cursor now records `caught_up` once a walk reaches its last list page. The check does not report this feed in `data_complete` yet, because it reads no Red Hat data; option B would add it.

**Other distros.**
- **AlmaLinux and Rocky Linux** rebuild RHEL and publish their own errata on their own schedule. A RHEL "Fix deferred" says nothing authoritative about whether Alma has shipped a fix.
- **SUSE and openSUSE** publish per-CVE CSAF VEX files (category `csaf_vex`), plus OVAL, in the `projects/security/csaf-vex/` directory of SUSE's FTP tree and its mirrors. SUSE's CVE pages show per-product states (Affected, Not affected, Already fixed). That is an equivalent source, not yet examined in detail: its package names and product IDs need the same study as this one.
- **Alpine:** `secdb` lists backported fixes only, and its maintainers say it is not a complete record of issues. The tracker at `security.alpinelinux.org` derives candidates from NVD and is known to have false positives and negatives. There is no authoritative unfixed source, so Alpine cannot earn `not_affected` from data.

## 2. Options

**A. Fix-only distros answer `unresolved` where they would answer `not_affected`.** This changes status only, needs no new data, and holds for every fix-only distro. A measurement over all distros on 2026-11-13 found eleven with no unfixed row, not six (design section 6 lists them). It is needed whatever else is decided, because B covers RHEL main streams only, and only once the Red Hat feed is complete. Built on 2026-11-13 (reason `distro_lists_fixes_only`).

**B. Read Red Hat's unfixed states in the check.** Recommended shape in section 3. RHEL main streams gain both an earned `not_affected` and an `affected` answer for CVEs Red Hat has not fixed. Today those CVEs are invisible, even under A.

**C. Same as B, but from Red Hat's CSAF VEX files** instead of the Security Data API. The states are the same, at the same source-package level, with richer product IDs and purls. It would mean a new adapter for data the existing adapter already receives, so it is not worth it now. Reconsider if the Security Data API is retired.

## 3. Recommended shape for B

1. **Scope:** RHEL 8, 9 and 10 main streams only (`cpe:/[ao]:redhat:enterprise_linux:N`), with plain package names. EUS, AUS, E4S, ELS, layered products, modules and containers stay under rule A. AlmaLinux and Rocky Linux also stay under A, for the reason in section 1.
2. **Storage:** a new global child table, written by the merge from the `redhat` source in the same delete-and-reinsert as the other child tables. For example `cve_vendor_package_states (cve_id, vendor, release, source_package, state)`, filled from a new `CanonicalPatch` field that the Red Hat adapter populates. Not in `cve_affected_packages`, because:
   - the rows are source-level and release-level, where existing rows are binary and repository-level;
   - `Under investigation` needs a state column that package rows lack;
   - adding them to `material_hash` would re-fire realtime alerts for every CVE with RHEL states on rollout, and change watchlist matching. That would be a separate decision.
3. **States:**
   - Affected, Fix deferred, Will not fix and Out of support scope make an advisory Affected for that release and source package, with no fixed version. The advisory is the CVE record, so `cve_ids` holds the CVE.
   - Under investigation makes the item `unresolved`.
   - Not affected adds nothing.
4. **Item to release:** `Red Hat:enterprise_linux:9::<repo>` maps to release 9. `Red Hat:enterprise_linux:10.<minor>` maps to release 10. Every other `Red Hat:` ecosystem has no states.
5. **Item to source name**, in this order:
   - (a) a new optional item field `source_name`. `rpm -q --qf '%{SOURCERPM}'` gives it, and Syft writes it in the RPM purl's `upstream` qualifier, which Grype matches on for the same reason.
   - (b) otherwise, the derived map from section 1, but only where it gives exactly one source.
   - (c) otherwise the item cannot use states and falls under rule A (`unresolved`, with a reason such as `distro_source_name_unknown`).
6. **When `not_affected` is allowed:** only if a source name is known, the Red Hat feed has caught up (a `caught_up` flag added to its cursor, and `data_complete` covering it for Red Hat items), there is no state row other than Not affected, and every OSV row clears the version.
7. **Staleness:** when Red Hat ships a fix, the CVE moves from `package_state` to `affected_release`, and the next feed run rewrites the rows. Until then a patched host reads `affected`. That error points toward caution, and the Red Hat feed runs every 12 hours.

## 4. Changes B needs

- **Migration:** the new table, its indexes (`release, source_package`), with no RLS, since it is global CVE data like `cve_affected_packages`.
- **Feed:**
  - the Red Hat adapter fills the new patch field;
  - `Out of support scope` added to `fixStatePriority`;
  - a `caught_up` flag in its cursor.
- **Merge:** delete and reinsert the rows in `canonicalize`.
- **Check:**
  - read the states in the same snapshot;
  - a source-name resolver (request field, then the derived map);
  - the state rules in the evaluation and in `setStatus`.
- **API:** the `source_name` item field, new reason enum values, and the status descriptions.
- **Re-ingest:** Red Hat states arrive only through the `redhat` feed. A full Red Hat backfill is two requests per CVE at 2 per second, which takes hours.
- **Before building, measure on a complete Red Hat ingest:**
  - map coverage per RHEL release;
  - the share of `rpm -qa` names from a stock RHEL 9 host that resolve to one source;
  - how many current-release RHEL 9 items would answer `not_affected` and how many `affected`.

## 5. Risks

- **Product and package naming drift.** Red Hat may rename CPEs or package-state product names. Anything outside the mapped forms falls back to rule A and never clears, so drift costs answers, not correctness.
- **A wrong derived map entry** could read a binary against another source's states. If the true source has an unfixed state that the wrong one lacks, that could clear wrongly. Taking only names that map to exactly one source, and letting a request's `source_name` win, limits this. The pre-build measurement should also check derived entries against `rpm` metadata from a real host.
- **Volume:** about 46,000 rows for RHEL 8 to 10 now. Small next to the 7.5 million package rows.
- **Value:** the design already leaves per-host distro matching to Trivy (design section 6, "Binary names"), and few distro items are expected at this endpoint. B is real work (a table, adapter, merge, check and API changes, plus a backfill) for RHEL main streams only.

## 6. Recommendation

Build rule A now (done 2026-11-13). It makes every fix-only distro correct, at the cost of never answering `not_affected` for them.

Defer B until RHEL clearing is a product need, for example a customer or an agent workflow that checks RHEL hosts here rather than with Trivy. When it is, build it as in section 3, after the pre-build measurement in section 4.

Treat SUSE the same way later, from its CSAF VEX files. Alpine stays under rule A.

**Decisions for Sam:**
1. Rule A now? (Decided 2026-11-13: yes, and built.)
2. B now, later, or never?
3. If B: a separate state table (recommended) or rows in `cve_affected_packages`?
4. If B: request field `source_name` plus the derived map (recommended), or either alone?
