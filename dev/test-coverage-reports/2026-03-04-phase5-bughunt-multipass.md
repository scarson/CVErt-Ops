# Bug Hunt Report — Phase 5 (Multi-Pass)

**Date:** 2026-03-04
**Variant:** BH-T (Multi-Pass)
**Model:** Claude Opus 4.6

## Scope

**Packages/files analyzed (15 files):**
- `internal/tier/resolver.go`, `internal/tier/limits.go`
- `internal/api/middleware_tier.go`, `internal/api/tier_cache.go`, `internal/api/org_ratelimit.go`, `internal/api/org_tier.go`
- `internal/retention/runner.go`, `internal/store/retention.go`
- `internal/audit/redact.go`, `internal/audit/writer.go`
- `internal/api/audit_log.go`, `internal/store/audit.go`
- `internal/crypto/aes.go`
- `internal/api/sso.go`, `internal/store/sso.go`

**All five passes performed:** Contract Violations, Cross-Sibling Pattern Violations, Failure Mode Reasoning, Concurrency Reasoning, Error Propagation.

---

## Bugs

### BUG-1: Runner.Run always returns nil — violates documented contract
**Location:** `internal/retention/runner.go:49-98`
**Severity:** significant
**Evidence:** The docstring on line 49-50 states: *"Returns nil unless the context is cancelled."* But `Run` always returns nil on line 97. When context is cancelled, `cleanupTable` logs and returns early (line 168-169), but `Run` itself never checks `ctx.Err()` and never returns it. Additionally, when `cleanupTierGated` fails (e.g., `ListAllOrgs` DB error at line 102), the error is logged on line 92 but `Run` still returns nil on line 97.
**Impact:** The job system cannot distinguish between a successful retention run and one where tier-gated cleanup silently failed due to a DB error or context cancellation. Data that should have been cleaned up may be retained without any job-level failure signal.
**Found in:** Pass 1 — Contract Violations

### BUG-2: putSSODomainsHandler missing audit log entry
**Location:** `internal/api/sso.go:425-471`
**Severity:** significant
**Evidence:** All three other SSO mutation handlers log audit entries: `createSSOHandler` (line 182), `patchSSOHandler` (line 361), `deleteSSOHandler` (line 412). But `putSSODomainsHandler` — which replaces the set of email domains controlling who can authenticate via SSO — has no `srv.auditLog(...)` call at all.
**Impact:** An admin could change which email domains are authorized for SSO login and there would be no audit trail. For a security product, SSO domain changes are high-sensitivity operations. An attacker with admin access could add their domain, authenticate, then remove it — leaving no record.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

### BUG-3: deleteSSOHandler returns 204 for non-existent connection
**Location:** `internal/api/sso.go:386-423`
**Severity:** minor
**Evidence:** `getSSOHandler` (line 218) and `patchSSOHandler` (line 269-271) both return 404 when `current == nil`. But `deleteSSOHandler` reads the current connection (line 397), then calls `DeleteSSOConnection` regardless of whether `current` is nil (line 404), and returns 204 (line 422). A DELETE against an org with no SSO connection gets a success response instead of 404.
**Impact:** API consumers cannot distinguish between deleting an existing connection and deleting nothing. While DELETE idempotency is a valid design choice, the inconsistency with sibling handlers is likely unintentional.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

### BUG-4: listAuditLogHandler silently ignores invalid cursor
**Location:** `internal/api/audit_log.go:117-123`
**Severity:** minor
**Evidence:** When `decodeTimeCursor(c)` returns an error (line 118-119), the error is silently discarded and `p.CursorCreatedAt`/`p.CursorID` remain nil. This means an invalid or corrupted cursor parameter causes the query to restart from the beginning (no cursor = first page) instead of returning a 400 error. Contrast with the `limit` and `actor_id` parameters (lines 62-66, 86-90) which both return 400 on parse failure.
**Impact:** A client with a stale or corrupted cursor receives page-1 results instead of an error. This could cause silent data duplication in paginated exports — the client thinks it's getting the next page but is actually re-reading from the start.
**Found in:** Pass 5 — Error Propagation

---

## Design Concerns

### redactSecrets does not recurse into slice values
**Location:** `internal/audit/redact.go:23-46`
The function recurses into nested `map[string]any` values (line 39-41) but not into `[]any` slices containing maps. If any audited entity type produces state with array-of-object fields containing sensitive keys (e.g., `{"items": [{"token": "xyz"}]}`), those secrets would leak into the audit log. Currently, all SSO audit entries use flat maps, so this is latent — but it becomes active if any future entity type has array-structured state.

### orgRateLimiter resets token bucket on tier change
**Location:** `internal/api/org_ratelimit.go:50-51`
When `Allow` detects that the stored limiter's rate or burst differs from the requested values (e.g., after a tier change or override update), it creates a brand-new `rate.Limiter` with a full token bucket. An org that just exhausted its rate limit gets a fresh allowance if their tier is modified. In theory, rapid tier toggling by an admin could repeatedly grant fresh bursts. Requires admin access, so not externally exploitable, but worth noting.

### audit.Writer.Log goroutines have no context timeout
**Location:** `internal/audit/writer.go:45`
`context.WithoutCancel(ctx)` removes the parent's cancellation and deadline. The goroutine's DB operations (`GetUserByID`, `InsertAuditEntry`) run with no timeout. If the DB pool is saturated during shutdown, `Flush()` (which calls `wg.Wait()`) could block indefinitely. Depends on pgxpool-level timeouts for protection.
