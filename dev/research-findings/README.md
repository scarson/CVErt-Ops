# Feed Research Findings

Per-feed implementation briefs produced by the `feed-researcher` subagent before each adapter was implemented. Each brief documents rate limits, response format, pagination, incremental sync, known quirks, and CVErt Ops compatibility requirements — verified against live upstream docs/APIs.

## Files

| File | Feed | Web-verified | Adapter commit |
|---|---|---|---|
| [nvd.md](nvd.md) | NVD API 2.0 | ✅ Yes (aee0846) | `272100f` |
| [osv.md](osv.md) | OSV GCS bulk ZIP | ⚠️ Partial — agents blocked from web; all.zip URL verified via `curl -I` | `b9ef19a` |
| [ghsa.md](ghsa.md) | GHSA REST API | ✅ Yes (aee0846) | `46925ee` |
| [epss.md](epss.md) | FIRST.org EPSS CSV | TBD | pending |

## Notes on Web Access

The `feed-researcher` agent tool list includes `WebSearch` and `WebFetch`, but two OSV research runs (aa7dcb2, a1df16c) reported web tools as "denied". The GHSA researcher (aee0846) and NVD researcher (ae5b848) worked fine. The root cause of the inconsistency is unknown. When web access is blocked, use `curl -I` via the Bash tool for URL verification and note the limitation in the brief.

The `feed-researcher` AGENT.md was updated to require web research explicitly and fail loudly (with `RESEARCH FAILED` message) rather than silently falling back to training data.
