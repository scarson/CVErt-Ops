# Feed Research Findings

Per-feed implementation briefs produced before each adapter is implemented. Each brief documents rate limits, response format, pagination, incremental sync, known quirks, and CVErt Ops compatibility requirements — verified against live upstream docs/APIs.

## Implemented Feeds

| File | Feed | Web-verified | Adapter commit |
|---|---|---|---|
| [nvd.md](nvd.md) | NVD API 2.0 | ✅ Yes (aee0846) | `272100f` |
| [osv.md](osv.md) | OSV GCS bulk ZIP | ⚠️ Partial — agents blocked from web; all.zip URL verified via `curl -I` | `b9ef19a` |
| [ghsa.md](ghsa.md) | GHSA REST API | ✅ Yes (aee0846) | `46925ee` |
| [epss.md](epss.md) | FIRST.org EPSS CSV | TBD | pending |

## Candidate Feeds (Researched, Not Yet Implemented)

| File | Feed | Priority | Auth | Notes |
|---|---|---|---|---|
| [msrc.md](msrc.md) | Microsoft MSRC CVRF/CSAF API | Tier 1 | None | Patch Tuesday data, KB articles, per-product exploitability |
| [redhat.md](redhat.md) | Red Hat Security Data API + CSAF/VEX | Tier 1 | None | Per-product fix status, Red Hat severity, RHEL package impact |
| [vulncheck.md](vulncheck.md) | VulnCheck API | Tier 2 | Bearer token (free tier) | Temporal CVSS, threat actors, exploit chains, NVD++ |
| [cisa-ics.md](cisa-ics.md) | CISA ICS-CERT CSAF Advisories | Tier 2 | None | ICS/SCADA/OT advisories via GitHub CSAF 2.0 |
| [cisco-psirt.md](cisco-psirt.md) | Cisco PSIRT openVuln API | Tier 3 | OAuth2 | Cisco-specific advisories, restrictive rate limits |
| [exploitdb.md](exploitdb.md) | ExploitDB | Tier 3 | None | No API — git CSV; exploit availability signal |
| [linux-kernel.md](linux-kernel.md) | Linux Kernel CVEs (kernel.org CNA) | Tier 3 | None | No API — git repo; high volume, flows to NVD |

## Priority Tiers

- **Tier 1:** High value, free, unauthenticated — should implement
- **Tier 2:** Valuable enrichment — worth considering based on user demand
- **Tier 3:** Niche audience or redundant signal — defer indefinitely

## Notes on Web Access

The `feed-researcher` agent tool list includes `WebSearch` and `WebFetch`, but multiple research runs have reported web tools as "denied". When web access is blocked, research is performed manually in the main conversation context. The `feed-researcher` AGENT.md requires web research explicitly and fails loudly (with `RESEARCH FAILED` message) rather than silently falling back to training data.

## CSAF Parser Reusability

Four candidate feeds use OASIS CSAF 2.0 format: MSRC, Red Hat, CISA ICS-CERT, and Cisco PSIRT. A shared CSAF parser would significantly reduce implementation effort for all four.
