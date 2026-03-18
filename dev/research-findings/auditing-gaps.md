# Audit Logging Gaps — Standards Analysis & Remediation Path

**Date:** 2026-03-18
**Context:** Identified during agent-readiness review of Phase 8 coverage remediation plan. P8 Tasks 2, 3, 7, 8 add audit logging to handlers using the existing fire-and-forget pattern. This document captures the compliance gaps in that pattern and the remediation path.

---

## Current Architecture

CVErt Ops has two fire-and-forget logging mechanisms:

### 1. Audit Log (`internal/audit/writer.go`)

`Writer.Log()` spawns a goroutine with `context.WithoutCancel`, writes to the DB via `store.InsertAuditEntry`, and logs errors via slog. Errors are never propagated to callers. The ABOUTME header states: "Non-blocking — errors are logged, never propagated to callers."

Called from HTTP handlers via `srv.auditLog(r, audit.Entry{...})` after successful mutations.

### 2. Security Event Log (`internal/secure/writer.go`)

Same pattern — async goroutine, semaphore-bounded (capacity 50 after HR C2), rate-limited, errors logged not propagated. Also forwards to syslog independently. Events are dropped (with `metrics.SecurityEventsDropped` counter) when the semaphore is full.

### Failure Modes

Both writers silently discard failed writes:
- **Audit writer:** `slog.Error("audit log insert", ...)` at `writer.go:71` — no metric, no alerting
- **Security event writer:** `slog.Error("security event write failed", ...)` at `writer.go:90` — no metric, no alerting
- **Crash before flush:** Both use goroutines that outlive the HTTP request. A process crash between handler return and goroutine completion loses the record permanently.
- **DB connection exhaustion:** During high load, audit writes may fail silently if the connection pool is saturated.

---

## Standards Analysis

### NIST SP 800-53 Rev 5 — AU Family

| Control | Title | Baseline | Relevance |
|---------|-------|----------|-----------|
| AU-2 | Event Logging | Low/Mod/High | Defines what events to log — CVErt Ops satisfies this |
| AU-3 | Content of Audit Records | Low/Mod/High | What/when/where/who/outcome — satisfied |
| AU-5 | Response to Audit Logging Process Failures | Low/Mod/High | **GAP: No alerting on failure** |
| AU-5(4) | Shutdown on Failure | **Not in any baseline** | Not implemented; not required |
| AU-5(5) | Alternate Audit Logging Capability | **Not in any baseline** | Not implemented; not required |
| AU-8 | Time Stamps | Low/Mod/High | Satisfied (DB timestamps) |
| AU-9 | Protection of Audit Information | Low/Mod/High | Satisfied (RLS, DB-level access control) |
| AU-10 | Non-repudiation | **High only** | **GAP: Fire-and-forget cannot guarantee irrefutable evidence** |
| AU-11 | Audit Record Retention | Low/Mod/High | Satisfied (retention policies) |
| AU-12 | Audit Record Generation | Low/Mod/High | Satisfied (audit calls in handlers) |
| AU-12(1) | System-wide Time-correlated Trail | High | Satisfied (single DB, UTC timestamps) |

### NIST SP 800-171 Rev 3 — Control 03.03.04

> "Alert organizational personnel or roles within [organization-defined time period] in the event of an audit logging process failure."

Possible responses include "overwriting oldest audit records, shutting down the system, and stopping the generation of audit records." Explicitly states: **"Organizations may decide to take no additional actions after alerting designated roles or personnel."**

**Status:** Not satisfied. Audit write failures go to slog but generate no operator-facing alert.

### IEC 62443-4-2 — CR 2.10 (Response to Audit Processing Failure)

Requires that the component "keep working in its essential functions, but also take action (like to issue an alarm)." Applicable at all security levels (SL-C 1 through SL-C 4).

**Status:** Partially satisfied. Essential functions continue (good), but no alarm is issued (gap).

---

## Gap 1: No Operator Alerting on Audit Failure (AU-5 Base)

### Problem

All three standards (NIST 800-53 AU-5, NIST 800-171 03.03.04, IEC 62443 CR 2.10) require alerting personnel when audit logging fails. Currently:

- Audit write failures produce `slog.Error` messages — visible only if someone watches structured logs in real time
- There is no Prometheus counter for audit write failures in either writer
- There is no mechanism to alert an operator (email, webhook, dashboard indicator) when audit logging is degraded

### Remediation (Low Effort)

**Add Prometheus failure counters to both writers.** This enables alerting via Grafana/Alertmanager, which is the standard observability-driven alerting path.

**Audit writer (`internal/audit/writer.go`):**
- New counter: `metrics.AuditWriteFailures` (define in new `internal/metrics/audit.go`)
- Increment at line 67 (marshal error) and line 72 (insert error)
- Requires adding `import "github.com/scarson/cvert-ops/internal/metrics"` — no circular dependency risk

**Security event writer (`internal/secure/writer.go`):**
- New counter: `metrics.SecurityEventsWriteFailed` (define in `internal/metrics/security.go`, alongside existing `SecurityEventsDropped`)
- Increment at line 93 (insert error)
- **Already imports `internal/metrics`** — pattern established with `SecurityEventsDropped.Inc()` at line 64

**Total code change:** ~8 lines (6-line counter definition + 1 line per error site).

**This does not add runtime alerting (email/webhook)** — it makes failure counts visible to Prometheus. Operators configure Alertmanager rules to fire alerts when the counter increases. This is the idiomatic approach for Go services and satisfies the "alert personnel" requirement.

### Scope Decision

This counter addition is small enough to fold into existing remediation tasks:
- HR C2 (already modifies `secure/writer.go`) — add `SecurityEventsWriteFailed` counter
- P8 Task 2 (first audit logging task) — add `AuditWriteFailures` counter as a prerequisite sub-step

Alternatively, it can be a standalone task after Stage 2.

---

## Gap 2: Non-Repudiation for Security-Critical Mutations (AU-10)

### Problem

AU-10 (Non-repudiation, HIGH baseline only) requires:

> "Provide irrefutable evidence that an individual (or process acting on behalf of an individual) has performed [organization-defined actions]."

The word **irrefutable** implies the evidence MUST exist. The current fire-and-forget architecture has two failure modes that can lose evidence:

1. **Crash before flush:** The async goroutine hasn't executed yet when the process crashes. The mutation committed to the DB, but the audit record was never written.
2. **Silent DB write failure:** The goroutine executes but the audit INSERT fails (connection exhaustion, constraint violation, disk full). The error is logged to slog and discarded.

In both cases, the mutation succeeded but the audit evidence does not exist. This violates AU-10's "irrefutable evidence" requirement for those specific actions.

### Tension with AU-5

AU-5 (base, all baselines) says organizations may "decide to take no additional actions" on audit failure — implying continued operation is acceptable.

AU-10 (HIGH only) requires irrefutable evidence exists.

NIST resolves this through control composition:
- Organizations implementing AU-10 are expected to also implement **AU-5(4)** (shutdown/degrade on failure) or **AU-5(5)** (alternate audit capability)
- Neither AU-5(4) nor AU-5(5) is in any baseline — they're selected during control tailoring when AU-10 is required

### Which Actions Need Non-Repudiation?

Not all actions require AU-10 protection. The organization defines which actions are in scope. For CVErt Ops, the security-critical mutations where non-repudiation matters are:

| Action Category | Examples | Why It Matters |
|----------------|----------|----------------|
| Alert configuration | Rule create/modify/delete | An attacker who disables alert rules can suppress vulnerability notifications |
| Monitoring scope | Watchlist create/modify/delete | Changing what's monitored affects coverage |
| Notification routing | Channel create/modify/delete, report binding | Redirecting notifications enables information suppression |
| Access control | Role changes, invitation acceptance, MFA reset | Privilege escalation / de-escalation |
| Organization policy | MFA requirements, registration mode, SSO config | Weakening security posture |
| User lifecycle | Disable/enable user, force password reset | Account takeover / lockout |

Actions that do NOT need non-repudiation:
- Automated CVE ingestion and enrichment (no human actor)
- Background job execution (system-initiated)
- Read-only API calls (no state mutation)

### Remediation Options (Higher Effort — Future Design Phase)

#### Option A: Synchronous Audit for Defined Actions

For handlers covering AU-10-scoped actions, write the audit record **inside the handler's database transaction**. If the audit INSERT fails, the transaction rolls back, and the mutation also fails.

```go
// Current pattern (fire-and-forget):
srv.store.CreateAlertRule(ctx, orgID, rule)  // commits
srv.auditLog(r, audit.Entry{...})           // async, may be lost

// Non-repudiation pattern (synchronous):
srv.store.WithOrgTx(ctx, orgID, func(tx *sql.Tx) error {
    if err := tx.CreateAlertRule(ctx, rule); err != nil {
        return err
    }
    return tx.InsertAuditEntry(ctx, auditEntry)  // fails → rolls back both
})
```

**Pros:** Simple, uses existing transaction infrastructure, guarantees atomicity.
**Cons:** Audit write latency added to every covered request. Transaction held longer. Requires identifying and modifying each covered handler.

#### Option B: WAL-Backed Async Audit

Write audit records to a local write-ahead log (embedded WAL or durable queue) synchronously before returning success. A background flusher moves records to the database.

**Pros:** Low-latency (local disk write). Survives crashes (WAL is durable). Decouples audit DB availability from handler latency.
**Cons:** New infrastructure component. Complexity of WAL management, replay, and deduplication. Not worth it unless the DB audit write latency is a measured problem.

#### Option C: Document as Known Limitation

Document that CVErt Ops's audit logging satisfies AU-5 (all baselines) and AU-12 (all baselines) but does NOT satisfy AU-10 (HIGH baseline). Customers requiring HIGH baseline non-repudiation should enable Postgres-level audit logging (e.g., pgAudit) as a defense-in-depth layer.

**Pros:** Zero code change. Honest compliance posture.
**Cons:** Limits the product's compliance story. Pushes complexity to the operator.

### Recommendation

**Short-term (current remediation):** Keep fire-and-forget. Add Prometheus failure counters (Gap 1 fix). Document AU-10 as a known gap.

**Medium-term (future design phase):** Implement Option A (synchronous audit) for AU-10-scoped actions only. This is the simplest path that actually satisfies AU-10. The list of covered handlers is well-defined (alert rules, watchlists, channels, reports, user management, org settings, SSO config). Non-covered handlers (CVE endpoints, read-only endpoints, background workers) continue using fire-and-forget.

**Rationale for Option A over B:** The WAL approach is over-engineered for this use case. Audit INSERT latency is a single DB round-trip (~1-5ms on localhost). Adding this to a handler that already does 2-5 DB round-trips is not a meaningful latency regression. The WAL is only justified if the audit DB is a separate system with higher latency or availability concerns — which is not the case for CVErt Ops's single-DB architecture.

---

## Summary

| Gap | Standard | Severity | Effort | Status |
|-----|----------|----------|--------|--------|
| No operator alerting on audit failure | AU-5 (all baselines), NIST 800-171 03.03.04, IEC 62443 CR 2.10 | Medium | ~8 lines of code | **Can fold into current remediation** |
| No non-repudiation for critical mutations | AU-10 (HIGH only) | Low (HIGH-only requirement) | Medium (handler-by-handler changes) | **Future design phase** |
