# Bug-hunt kickoff — suspected bugs from the 2026-06-05 S6 reports/AI/retention audit

Run: `bug-hunt-cycle` with the scope below.

**Scope:** `internal/notify/digest.go`, `internal/store/queries/cves.sql` (DigestCVEs), scheduled-report
config. Surfaced during S6.

**Seed findings (verify, don't trust):**
- **[PRIORITY] Digest reports ignore `watchlist_ids` — whole-corpus digest regardless of scoping** —
  `internal/notify/digest.go:107-175` → `DigestCVEs` (`cves.sql:166-184`) applies no watchlist/org
  narrowing. A scheduled digest scoped to a watchlist may instead send a whole-corpus digest. Confirm the
  intended scoping; user-facing correctness impact if real.
- **`report.AiSummary` flag never honored** — the LLM summarizer is stored and round-tripped but not wired
  into the digest/render path. Dead flag (functional gap). Confirm whether AI summaries are meant to be live.

Noticed while auditing performance; NOT investigated. Leads, not confirmed bugs. SB2 (watchlist scoping) is the priority.
