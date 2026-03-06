# Linux Kernel CVEs (kernel.org CNA) — Research Findings

> **Researched:** 2026-03-05
> **Agent:** manual research via WebSearch + WebFetch (feed-researcher agents blocked from web tools)
> **Sources:** [Kernel CVE Process](https://docs.kernel.org/process/cve.html), [LWN: Kernel becomes CNA](https://lwn.net/Articles/961961/), [vulns.git (Google mirror)](https://kernel.googlesource.com/pub/scm/linux/kernel/git/lee/vulns/), [linux-cve-announce mailing list](https://lore.kernel.org/linux-cve-announce/), [linux-cve-analysis](https://github.com/cloud-lts/linux-cve-analysis), [nluedtke/linux_kernel_cves](https://github.com/nluedtke/linux_kernel_cves)

---

## Overview

The Linux kernel project became a CVE Numbering Authority (CNA) and now issues its own CVEs for kernel security issues. CVEs are assigned automatically during the stable release process when potentially security-relevant bugfixes are identified.

- **CNA scope:** Linux kernel only
- **Data repository:** `https://git.kernel.org/pub/scm/linux/security/vulns.git`
- **Google mirror:** `https://kernel.googlesource.com/pub/scm/linux/kernel/git/lee/vulns/`
- **Mailing list:** `https://lore.kernel.org/linux-cve-announce/`
- **Subscribe:** `https://subspace.kernel.org/subscribing.html`
- **Auth:** None — public git repository
- **Contact:** `cve@kernel.org`

## Data Format

- **Repository format:** Git repo with per-CVE files
- **File types:** `.dyad` files and CVE 5.0 JSON (cvelistV5 format)
- **Branches:** `master` (stable) and `wip` (work-in-progress)
- **Organization:** Files organized by CVE ID, tracking affected files and fix/break commits

### Per-CVE data includes:

| Data | Notes |
|---|---|
| CVE ID | Standard CVE identifier |
| Fix commit SHA(s) | Git commit hash(es) that fix the vulnerability |
| Break commit SHA(s) | Git commit hash(es) that introduced the vulnerability |
| Affected kernel versions | Range of vulnerable versions |
| Fixed kernel versions | Stable versions containing the fix |
| Affected files | Source files impacted |

## CVE Assignment Process

- CVEs are assigned **only after fixes are merged** into stable kernel trees
- Assignment is automatic during the normal stable release process
- Developers responsible for CVE assignments identify potentially security-relevant changes
- **No CVEs for unfixed issues** — only assigned when a fix exists
- **No CVEs for unsupported versions** — only actively maintained Stable/LTS kernel versions
- **Broad assignment policy:** "Almost any bug might be exploitable" — kernel CNA assigns CVEs broadly, leading to high volume

## Rate Limits

Not applicable — git-based consumption. Standard git hosting rate limits apply.

## Incremental Sync

- **Strategy:** `git pull` on cloned vulns.git repo
- **Change detection:** Parse new/modified files since last sync
- **Mailing list:** Subscribe to `linux-cve-announce` for push notifications
- **Cadence:** New CVEs assigned with each stable kernel release (approximately weekly)

## Known Quirks

1. **Extremely high volume** — kernel CNA takes a conservative approach and assigns CVEs broadly. Hundreds of CVEs per year, many for bugs with limited practical exploitability.
2. **CVEs only for fixed issues** — no CVE is assigned until a fix is merged. Zero-day or unpatched issues don't get kernel CNA CVEs.
3. **Only supported kernel versions** — CVEs not assigned for EOL kernel versions, even if affected.
4. **Data flows to MITRE/NVD eventually** — kernel CNA CVEs are published to the CVE program and appear in NVD, typically with some delay. The vulns.git repo provides earlier access.
5. **`.dyad` file format** — non-standard format specific to kernel tooling. Requires custom parser.
6. **cvelistV5 JSON** — standard CVE 5.0 JSON format, compatible with MITRE's schema. This is the more portable format.
7. **Fix commits are the primary data** — the unique value is kernel-specific: git commit SHAs that fix and introduce vulnerabilities. Useful for determining if a specific kernel build is affected.
8. **No CVSS scores** — kernel CNA does not assign CVSS scores. NVD enrichment provides these later.
9. **Kernel-specific applicability** — knowing if a CVE affects your system requires understanding your kernel configuration, as most users build/run only a subset of kernel features.
10. **Mailing list as notification channel** — `linux-cve-announce` provides push notifications but in email format, not structured data.

## Bulk Source

- **Git clone:** `git clone https://git.kernel.org/pub/scm/linux/security/vulns.git`
- **Full history** available in the repository

## Assessment for CVErt Ops

**Unique value:** Earlier access to kernel CVEs than NVD (kernel CNA publishes before NVD processes). Fix commit SHAs enable precise kernel version impact analysis. Break commit SHAs identify when vulnerabilities were introduced.

**Implementation priority:** Tier 3 (Defer) — very high noise-to-signal ratio due to broad CVE assignment. Data flows to NVD/MITRE anyway with modest delay. The unique data (commit SHAs, version ranges) is only valuable for kernel-specific workflows. Git-based consumption with non-standard file formats adds complexity.

**Recommended approach:** If implemented, consume cvelistV5 JSON files (standard format). Treat as early-access CVE source that provides data before NVD processes it. Version range and commit SHA data could enrich existing CVE records. Consider whether the volume and noise level justify the implementation effort.

## CVErt Ops Patterns Required

- [ ] Alias resolution — NOT required (uses standard CVE IDs assigned by kernel CNA)
- [x] Withdrawn tombstoning — check for rejected/revoked CVEs in the repo
- [ ] ZIP temp-file — NOT required
- [ ] NVD-specific patterns — NOT applicable
- [ ] EPSS two-statement pattern — NOT applicable
- [x] Git-based sync — clone + pull instead of HTTP API
- [x] CVE 5.0 JSON parsing — standard cvelistV5 format (shared with MITRE adapter)
- [x] Custom `.dyad` parser — if consuming dyad files for commit SHA data
- [x] High-volume handling — broad CVE assignment means many records per sync
- [x] Dedup with NVD/MITRE — same CVE IDs will appear in NVD later
