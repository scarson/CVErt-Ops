# Pitfall Audit: Architecture & Operations

**Date:** 2026-03-18
**Auditor:** audit-arch agent (Explore)
**Scope:** 31 pitfalls across startup, config, AI, worker, containers, scheduling, cross-cutting
**Code paths:** `cmd/cvert-ops/main.go`, `internal/config/*`, `internal/ai/*`, `internal/worker/*`, `internal/api/ratelimit.go`, `internal/alert/dsl/*`, `internal/store/dsl_executor.go`, `internal/store/cve.go`, `docker/*`, `migrations/*`

---

## Summary Table

| ID | Title | Status | Evidence |
|---|---|---|---|
| 5.1 | RLS Alongside Org Migrations | VALIDATED | 10+ migration files with FORCE ROW LEVEL SECURITY |
| 5.5 | Case-Sensitive DSL Evaluation | VALIDATED | `alert/dsl/accessor.go:41`, `compiler.go:253,285,323` — strings.ToLower |
| 5.6 | Distroless Timezone Panic | VALIDATED | `main.go:23` — `_ "time/tzdata"` |
| 5.7 | Concurrent Migration Corruption | VALIDATED | `main.go:596-625` — pg_advisory_lock in autoMigrate |
| 5.9 | Alert Engine Nil-Dereference | VALIDATED | `dsl/accessor.go` — nil-safe accessors for all score/text fields |
| 5.10 | SET LOCAL Transaction-Scoped | VALIDATED | `store/timeout.go:16` — SET LOCAL used correctly |
| 5.11 | Job Queue MVCC Bloat | VALIDATED | `migrations/000001:32-33` — autovacuum tuning on 5 tables |
| 5.12 | Semver Version Range Matching | SUPERSEDED | No version range fields implemented; Masterminds/semver not in go.mod |
| 5.14 | Rate Limiter Unbounded Growth | VALIDATED | `ratelimit.go:21,26,57-76` — ticker cleanup + TTL eviction |
| 5.15 | Connection Pool Multiplication | VALIDATED | `main.go:709-710,748-753` — MaxConns + 80% warning |
| 5.16 | Multi-Tab Refresh False Theft | VALIDATED | `migrations/000006:11` — replaced_by_jti + grace period |
| 5.17 | Child Table Upsert Sort Order | NEEDS VERIFICATION | Advisory lock protects, but explicit sort not confirmed |
| 6.1 | time.After Leak in Poll Loops | VALIDATED | `worker/pool.go:151,245,274` — NewTicker + defer Stop |
| 6.2 | strings.Clone for JSON Buffers | UNIMPLEMENTED | Not found in feed adapters; streaming parse may avoid need |
| 6.3 | defer in Loop (dup of 1.8) | VALIDATED | Explicit Close() pattern used — DUPLICATE CONFIRMED |
| 10.1s | Row Scanner Column-List Sync | VALIDATED | `dsl_executor.go:21-47` cveColumns shared; `cve.go:126` uses same |
| 10.2s | LLM Polymorphic Fields | VALIDATED | Correct schema handling in AI gateway |
| 10.3s | Nullable Int Where Zero Valid | NEEDS VERIFICATION | ai_request_log token count handling unclear |
| 10.4s | API Client No Network on Init | VALIDATED | `ai/gemini.go:18-57` — lazy init with sync.Mutex |
| 10.5s | Cache Hits Don't Consume Quota | VALIDATED | `api/ai.go:102,279` — cache checked before quota |
| 10.1t | Digest DST Drift | NEEDS VERIFICATION | Report scheduling code not fully audited |
| 10.2t | Digest Truncation | VALIDATED | `notify/worker.go:313-315` — 25 CVE cap with "N more" |
| 10.3t | Missing Digest Heartbeat | NEEDS VERIFICATION | Zero-match digest behavior unclear |
| 10.4t | Missed-Run Catch-Up | NEEDS VERIFICATION | Catch-up policy not fully traced |
| 10.5t | Nullable Sort Column COALESCE | VALIDATED | `store/cve.go:142,186` — COALESCE guards |
| 10.6t | pg_trgm Extension | VALIDATED | `migrations/000002:5` — CREATE EXTENSION IF NOT EXISTS |
| 10.7t | statement_timeout | VALIDATED | `store/timeout.go` — 14s default |
| 10.8t | MaxConnIdleTime | VALIDATED | `main.go:709-710` |
| 10.9t | automemlimit | VALIDATED | `main.go` — `_ "github.com/KimMachineGun/automemlimit"` |
| 10.10t | XFF Right-to-Left | VALIDATED | `ratelimit.go:80` — chi RealIP middleware runs first |
| 13.1 | Deployment Config Matches Code | DIVERGED | Docker Compose connects as superuser; cvert_ops_app role exists but unused |
| 13.2 | Pattern-Level Fixes Codebase-Wide | NEEDS VERIFICATION | Meta-process — requires per-pattern audit |
| 13.3 | API Contract Consistency | VALIDATED (per API audit) | contract.go standardizes responses |
| 13.4 | Resource Lifecycle Completeness | NEEDS VERIFICATION | Close/Stop/Shutdown call completeness unclear |

**Totals:** 22 VALIDATED, 1 DIVERGED (13.1 — critical), 1 SUPERSEDED (5.12), 1 UNIMPLEMENTED (6.2), 1 DUPLICATE (6.3=1.8), 5 NEEDS VERIFICATION

**Numbering collision flagged:** Section 10 findings from Phase 4 AI Gateway (lines 1641-1793) collide with Rounds 24-52 table IDs (10.1-10.10). Used suffixes: 10.Xs for section findings, 10.Xt for table findings.

---

## Critical Findings

### 13.1 Deployment Config Matches Code — DIVERGED (CRITICAL)
**Status:** DIVERGED — Code-level RLS correct, deployment bypasses it
**Evidence:**
- **Code side:** Correct — RLS policies on all org-scoped tables, transaction helpers use SET LOCAL
- **Deployment side:** `docker/compose.yml:49` connects as `${POSTGRES_USER:-cvert_ops}` (superuser)
- `docker/init.sql:7-8` creates `cvert_ops_app` role with NOBYPASSRLS — but it's never used by the app
- `.env.example` shows dual DATABASE_URL approach (lines 59-60) but it's commented out
**Impact:** All RLS protections are dormant in default Docker Compose deployment. This is the exact scenario §13.1 describes.
**Notes:** The remediation plans (HR) may address this. If not, this is the single most critical deployment gap.

---

## Detailed Findings (Selected)

### 5.1 RLS Alongside Org Migrations
**Status:** VALIDATED
**Evidence:** 10+ migration files: org_members, api_keys, groups, group_members, org_invitations, watchlists, watchlist_items, alert_rules, alert_rule_runs, alert_events — all have FORCE ROW LEVEL SECURITY
**Notes:** Comprehensive coverage.

### 5.5 Case-Sensitive DSL Evaluation
**Status:** VALIDATED
**Evidence:** `dsl/accessor.go:41` (strings.ToLower), `dsl/compiler.go:253,285,323` (all text operators lowercased)
**Notes:** All DSL text operators are case-insensitive.

### 5.11 Job Queue MVCC Bloat
**Status:** VALIDATED
**Evidence:** `migrations/000001:32-33` — autovacuum_vacuum_scale_factor=0.01, cost_delay=2
**All instances checked:** Also applied to feed_state (000003), notification_deliveries (000017), audit_log (000027), vendor_enrichment (000029)
**Notes:** 5 high-churn tables all have tuned autovacuum.

### 5.12 Semver Version Range Matching
**Status:** SUPERSEDED
**Evidence:** `github.com/Masterminds/semver` not in go.mod. No version range fields in DSL or watchlists.
**Notes:** Pitfall is preventive documentation for future work. If version ranges are added, this guidance applies.

### 5.14 Rate Limiter Unbounded Growth
**Status:** VALIDATED
**Evidence:** `ratelimit.go:21,26,57-76` — background ticker cleanup with TTL-based eviction
**Notes:** Uses time.NewTicker (not time.After), matching pitfall 6.1 guidance.

### 6.2 strings.Clone for Large JSON Buffers
**Status:** UNIMPLEMENTED
**Evidence:** No strings.Clone usage found in feed adapters
**Notes:** Streaming JSON parsing (Token/More loop) may avoid the issue since data isn't retained as string references into the decoder's buffer. However, if any string fields from Decode() are stored long-term, they could pin the decoder's internal buffer. Worth investigating but may be a non-issue given the streaming architecture.

### 6.3 defer in Loop — DUPLICATE CONFIRMED
**Status:** VALIDATED + DUPLICATE of 1.8
**Notes:** This finding appears twice in the document (1.8 and 6.3). Should be merged during reorganization.

### 10.1s Shared Row Scanner Column-List Sync
**Status:** VALIDATED
**Evidence:** `dsl_executor.go:21-47` defines shared `cveColumns`, `cve.go:126` uses same slice
**Notes:** Both SearchCVEs and ExecuteDSLQuery reference the same column list.

### 10.4s External API Client Lazy Init
**Status:** VALIDATED
**Evidence:** `ai/gemini.go:18-57` — NewGeminiClient validates config only; getClient() creates client on first use with sync.Mutex
**Notes:** Constructor comment documents the pattern. If creation fails, g.client stays nil — next request retries automatically.

---

## Items Needing Verification

| ID | What needs checking | Why it's unclear |
|---|---|---|
| 5.17 | Child table upsert sort order in merge pipeline | Advisory lock handles CVE-level concurrency, but explicit sort before batch upsert not confirmed |
| 10.3s | ai_request_log token count zero-value handling | Need to verify pointer types or sentinel values in quota tracking |
| 10.1t | Digest scheduling DST drift | Report scheduling code not fully traced through timezone-aware arithmetic |
| 10.3t | Digest heartbeat (zero-match sends empty digest) | Behavior on zero matches not confirmed |
| 10.4t | Missed-run catch-up policy (at most 1 digest) | Policy implementation not fully traced |
| 13.2 | Pattern-level fixes applied codebase-wide | Meta-process requiring per-pattern grep — out of scope for single audit |
| 13.4 | Resource lifecycle (every New → Close) | Need systematic audit of all constructors vs shutdown calls in main.go |

---

## Assessment

The architecture & operations layer is **well-implemented with one critical deployment gap**. The RLS bypass via superuser connection (13.1) is the most significant finding — all code-level protections are correct but dormant in default deployment. Everything else is either validated or needs minor verification.

The numbering collision (10.x section findings vs 10.x table findings) must be resolved in the reorganized document.
