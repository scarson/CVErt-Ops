# Store Layer Test Coverage Review — Hybrid Analysis

**Package:** `internal/store/` (non-generated files only)
**Date:** 2026-03-03
**Method:** Two-pass hybrid (coverage-guided triage + semantic analysis)

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Security-critical | 4 |
| Correctness | 8 |
| Nice-to-have | 14 |
| Assertion quality | 3 |

**Production bugs found:** 0

---

## Pass 1: Coverage-Guided Triage

### The 87.5% Systematic Pattern — Confirmed

The ubiquitous 87.5% pattern across ~40 store methods is explained by one structural cause: **the error branch after the transaction helper wrapper call is never exercised**. Every method that delegates to `withOrgTx`, `withBypassTx`, or `withOrgRawTx` has this shape:

```go
err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
    // ... work ...
})
if err != nil {       // <-- this is the uncovered ~12.5%
    return nil, err
}
```

Since integration tests use a healthy Postgres that never fails `BeginTx` or `SET LOCAL`, this outer `if err` branch is systematically untested. **This is architectural, not an oversight.** Testing it would require injecting a broken DB, which has marginal value given the wrapper's simplicity.

**Verdict:** Nice-to-have for all 87.5% methods. Not filing individual findings for each instance.

---

### Transaction Helpers (store.go)

#### withBypassTx — 71.4%

| Uncovered Branch | Severity |
|------------------|----------|
| `BeginTx` error (line 52-53) | Nice-to-have |
| `SET LOCAL` error (line 62-63) | Nice-to-have |
| `panic` recovery path (lines 56-59) | **Correctness** |

**Finding C1:** The panic recovery path in `withBypassTx` is never tested. If a query panics inside the callback, the deferred `recover()` should rollback and re-panic. This is a correctness gap: a panic during a bypass-RLS transaction that fails to rollback could leave a stale connection with `bypass_rls = 'on'` in the pool. Since `SET LOCAL` resets on disconnect (not just rollback), the risk is mitigated by pgxpool connection lifecycle, but the recovery behavior itself is not verified.

#### withOrgRawTx — 64.3%

| Uncovered Branch | Severity |
|------------------|----------|
| `BeginTx` error (line 80) | Nice-to-have |
| `SET LOCAL` error (line 89-91) | Nice-to-have |
| `panic` recovery path (lines 83-87) | **Correctness** |
| `fn(tx)` error + rollback (line 93-95) | Nice-to-have |

**Finding C2:** Same panic recovery gap as withBypassTx, but for org-scoped raw transactions. The `withOrgRawTx` panic handler has the same pattern: `recover()` -> `rollback` -> `re-panic`. Never exercised. The risk here is slightly higher because `app.org_id` could remain set on a pooled connection if rollback fails silently.

#### OrgTx — 77.8%

| Uncovered Branch | Severity |
|------------------|----------|
| `pool.Begin` error (line 117) | Nice-to-have |
| `tx.Exec SET LOCAL` error (line 123-124) | Nice-to-have |

Note: OrgTx uses `defer tx.Rollback(ctx)` instead of explicit `recover()`. Rollback is idempotent after commit, so this is safe. No panic recovery gap here.

#### WorkerTx — 77.8%

| Uncovered Branch | Severity |
|------------------|----------|
| `pool.Begin` error (line 137) | Nice-to-have |
| `tx.Exec SET LOCAL` error (line 141-142) | Nice-to-have |

Same structure as OrgTx — `defer tx.Rollback(ctx)` handles cleanup. No panic recovery gap.

---

### BootstrapFirstUserOrg — 58.8% (org.go lines 66-123)

| Uncovered Branch | Severity |
|------------------|----------|
| `BeginTx` error (line 68-70) | Nice-to-have |
| `SET LOCAL` error (line 79-82) | Nice-to-have |
| Advisory lock error (line 87-90) | Nice-to-have |
| User count query error (line 93-96) | Nice-to-have |
| `CreateOrg` error (line 104-108) | **Correctness** |
| `CreateOrgMember` error (line 109-116) | **Correctness** |
| `tx.Commit()` error (line 118-120) | Nice-to-have |

**Finding C3:** BootstrapFirstUserOrg has 7 error branches; only the happy path (sole user creates org) and the multi-user-returns-nil path are tested. The `CreateOrg` failure within the bootstrap transaction is untested — if org creation fails after the advisory lock is acquired, the rollback behavior and error propagation are not verified. This matters because BootstrapFirstUserOrg manages its own transaction (not using `withBypassTx`), so any mistake in its manual error handling wouldn't be caught by the wrapper tests.

**Finding C4:** The `CreateOrgMember` failure branch after successful `CreateOrg` is untested. If member creation fails, the transaction should rollback the org creation too. This is a multi-step write where partial state is dangerous — an org without an owner would be orphaned.

---

### Auth Functions (auth.go) — 66.7% Pattern

All of: `UpdateLastLogin`, `UpdatePasswordHash`, `UpsertUserIdentity`, `CreateRefreshToken`, `MarkRefreshTokenUsed` — each at 66.7%.

| Uncovered Branch | Severity |
|------------------|----------|
| `fmt.Errorf` wrapping branch on each | Nice-to-have |

These are thin wrappers around sqlc calls. The uncovered branch is the `if err != nil { return fmt.Errorf(...) }` after the sqlc call. Since the sqlc call itself is exercised by the happy path, the only gap is the error wrapping. Low risk.

**CountUsers** (75%), **IncrementTokenVersion** (75%), **DeleteExpiredRefreshTokens** (75%): Same pattern, same verdict.

---

### Notification Delivery (notification_delivery.go)

#### UpsertDelivery — 66.7%

| Uncovered Branch | Severity |
|------------------|----------|
| `BeginTx` error (line 39-41) | Nice-to-have |
| `SET LOCAL` error (line 44-45) | Nice-to-have |

**Finding S1 (semantic):** UpsertDelivery manages its own transaction manually (lines 38-51) instead of using `withBypassTx`. The comment explains why: the raw SQL must execute on the same connection as the SET LOCAL. This is architecturally correct, but it means UpsertDelivery does NOT get the panic recovery that `withBypassTx` provides. If `tx.ExecContext` on the upsert SQL panics, the deferred `tx.Rollback()` will fire, but unlike `withBypassTx`, there is no `recover()` — the panic propagates immediately. This is actually fine (deferred Rollback runs before panic propagation), but it's worth noting the divergence.

#### MarkDeliveriesProcessing, CompleteDelivery, RetryDelivery, ExhaustDelivery — all 80%

All follow the standard `withBypassTx` wrapper pattern. The uncovered 20% is the outer `if err != nil` branch. Nice-to-have.

#### ResetStuckDeliveries — 80%

Same pattern. Nice-to-have.

#### ListDeliveries, GetDelivery, ReplayDelivery — 80-85%

These use `withOrgTx`. The uncovered branches are the outer error wrapping. Nice-to-have.

#### InsertDigestDelivery — 87.5%

Standard pattern. Nice-to-have.

---

### CVE Functions (cve.go)

#### ListCVEs — 0%

**Finding C5:** `ListCVEs` is completely untested. It is a simple passthrough to `s.q.ListCVEs(ctx, params)` — no logic, no branching beyond what sqlc generates. Risk: low. But for completeness, a basic smoke test confirming it returns an empty slice on an empty corpus would be appropriate.

#### SearchCVEs — 91.5%

Uncovered branches are in the filter-building logic. Since the test file exercises many filter combinations, the gap is likely one specific filter path (e.g., the `EPSSMax` with COALESCE sentinel, or the `CWEID` containment check). **This is well-covered.**

#### GetCVEDetail — 76.9%

| Uncovered Branch | Severity |
|------------------|----------|
| `GetCVEReferences` error (line 44-46) | Nice-to-have |
| `GetCVEAffectedPackages` error (line 48-50) | Nice-to-have |
| `GetCVEAffectedCPEs` error (line 52-54) | Nice-to-have |

Sequential child-table fetches: the happy path is tested (CVE exists, child rows fetched), but individual child-table query failures are not tested. Low risk since the error wrapping is straightforward.

#### GetCVESnapshot — 83.3%

Standard `ErrNoRows` + error wrapping pattern. Nice-to-have.

---

### Alert Rules (alert_rule.go)

#### CreateAlertRule — 90.9%

| Uncovered Branch | Severity |
|------------------|----------|
| Outer `if err != nil` after `withOrgTx` (line 100-102) | Nice-to-have |

**Finding AQ1 (assertion quality):** Tests verify rule creation returns a non-nil rule, but don't verify all fields (e.g., `HasEpssCondition`, `IsEpssOnly`, `FireOnNonMaterialChanges` boolean fields). The sqlc mapping could silently swap parameter positions for boolean fields and the test would still pass.

#### InsertAlertEvent — 87.5%

The ON CONFLICT DO NOTHING semantics with `ErrNoRows` detection (lines 266-269) is well-tested: both the "new event inserted" and "duplicate suppressed" paths are covered. Good.

#### ListAlertRules — 86.4%

Uses `withOrgRawTx` + squirrel. The uncovered branch is the query-build error path (line 192-193) which squirrel would only produce if given invalid SQL fragments.

#### ListAlertEvents — 90.3%

Similar to ListAlertRules. Well-covered.

#### ListActiveRulesForEvaluation / ListActiveRulesForEPSS — 87.5%

Standard bypass pattern. Nice-to-have.

---

### Alert Rule Channels (alert_rule_channel.go)

#### BindChannelToRule — 75%, UnbindChannelFromRule — 75%, ListChannelsForRule — 87.5%

Standard org-scoped pattern. The 75% methods have both the inner `fmt.Errorf` wrapping and the outer error branch uncovered.

#### ListActiveChannelsForFanout — 87.5%

**Finding S2 (security):** `ListActiveChannelsForFanout` uses `withBypassTx` because it is called from the worker path. Tests verify it returns signing secrets (good), but do not verify that the returned `SigningSecret` value is actually a valid 64-character hex string. The test checks `got.SigningSecret.String != ""` but not the format. This is an assertion quality gap — if `generateSigningSecret` ever returns a truncated value, the test wouldn't catch it.

#### ChannelRuleBindingExists — 87.5%

Standard pattern. Good cross-org isolation tests exist.

---

### API Keys (apikey.go)

#### LookupAPIKey — 83.3%

**Finding S3 (security):** `LookupAPIKey` is the auth hot-path and correctly uses `withBypassTx`. Tests cover the happy path (key found) and not-found path (returns nil, nil). However, there is no test verifying that expired keys are NOT returned. The SQL query presumably has a `WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())` clause — tests should verify that an expired key returns nil.

#### CreateAPIKey — 87.5%

Standard pattern. Well-tested including RLS isolation.

#### RevokeAPIKey — 75%

Standard pattern. Inner + outer error branches uncovered.

---

### Jobs (jobs.go)

#### ClaimJob — 83.3%

`ClaimJob` uses `s.q.ClaimJob` directly (no transaction wrapper). This is correct because the `job_queue` table has no RLS. The `ErrNoRows` → `(nil, nil)` path is tested.

#### CompleteJob, FailJob — 66.7%

**Finding C6:** `CompleteJob` and `FailJob` use `s.q` directly (no transaction wrapper), which is correct since `job_queue` has no RLS policies. But neither has a test verifying that calling CompleteJob on a non-existent job ID is handled correctly. If the sqlc query uses `UPDATE ... WHERE id = $1` without `RETURNING`, a no-op is silently accepted. If it uses `RETURNING`, it would return `ErrNoRows`. The test should document the expected behavior.

#### RecoverStaleJobs — 75%

Standard pattern. Nice-to-have.

---

### DSL Executor (dsl_executor.go)

#### scanCVERow — 75%

The uncovered 25% is the `rows.Scan` error branch. Nice-to-have.

#### encodeDSLCursor — 75%

The uncovered branch is the `json.Marshal` error, which cannot realistically fail for a struct of (time.Time, string). Nice-to-have.

#### decodeDSLCursor — covered via ExecuteDSLQuery tests

#### ExecuteDSLQuery — 84.2%

Queries `s.db` directly (no transaction wrapper), which is correct: cves is a global table with no RLS. The uncovered branches are query-build errors and row-scan errors. Nice-to-have.

---

### Notification Channel (notification_channel.go)

#### generateSigningSecret — 75%

The uncovered branch is `rand.Read` error, which only occurs if the OS entropy source fails. Nice-to-have.

#### RotateSigningSecret — 84.6%

**Finding S4 (security):** `RotateSigningSecret` atomically promotes `signing_secret → signing_secret_secondary` and sets a new primary. Tests verify that after rotation, `SigningSecretSecondary` is set. However, no test verifies that the secondary value equals the pre-rotation primary. The test confirms the new primary is returned and the secondary is non-empty, but doesn't assert the old-to-secondary promotion chain. If the SQL accidentally set secondary to NULL or a new random value instead of the old primary, the grace-period dual-validation pattern would silently break.

#### CreateNotificationChannel — 87.5%

Tests verify webhook channels get a signing secret and email channels don't. Good.

---

### Retention (retention.go) — All 10 functions at 87.5%

All follow the identical `withBypassTx` wrapper pattern. The uncovered branch on each is the outer `if err != nil` after the wrapper. Nice-to-have across the board.

---

### Group (group.go) — All functions 75-90%

Standard org-scoped pattern throughout. No specific findings beyond the 87.5% systematic pattern.

#### AddGroupMember — 90%

Uses `ON CONFLICT DO NOTHING` for idempotency. Tests confirm idempotent adds. Good.

---

### AI (ai.go)

#### IncrementAIUsage — 87.5%

Standard pattern. Test confirms counter increments.

#### GetAIQuotaOverride — 87.5%

The `ErrNoRows` → `(0, false, nil)` path is tested. Good.

#### toNullInt32, toNullString — 100%

Full coverage on helper functions. Good.

---

### Audit (audit.go)

#### InsertAuditEntry — 100%

Full coverage. Good.

#### ListAuditEntries — 88.9%

Uncovered: the `if err != nil` after the sqlc query. Nice-to-have.

#### fromNullUUID — 66.7%

The `Valid = true` branch (returning `&v.UUID`) is likely uncovered. Tests may only exercise the `nil` case. Nice-to-have since this is a trivial helper.

---

### SSO (sso.go)

#### SetSSOEmailDomains — 85.7%

Delete-all-then-insert pattern within a single `withOrgTx`. The uncovered branch is the per-domain insert error (`UpsertSSOEmailDomain` failure mid-loop). Nice-to-have.

#### LookupSSOByDomain — 83.3%, GetSSOConnectionByID — 83.3%

Both use `withBypassTx` (auth-path). Standard `ErrNoRows` handling. Nice-to-have.

---

### Watchlist (watchlist.go)

#### ListWatchlists — 85%

Uses `withOrgRawTx` + squirrel with `GROUP BY` for `item_count`. Well-tested.

#### ValidateWatchlistsOwnership — 87.5%

Tests cover the empty-slice shortcut (vacuous truth) and the ownership check. Good.

#### DeleteWatchlist, DeleteWatchlistItem — 75%

Standard pattern. Inner + outer error branches uncovered.

---

### Saved Search (saved_search.go)

#### All CRUD — 88-100%

Well-covered. `CleanupOrphanedPrivateSavedSearches` — 100%.

---

### Scheduled Report (scheduled_report.go)

#### ClaimDueReports — 87.5%

Standard `withBypassTx` wrapper pattern.

#### AdvanceReport — 100%

Full coverage. Good.

---

### Report Channel (report_channel.go)

#### ChannelHasActiveBindings — 83.3%

**Finding AQ2 (assertion quality):** `ChannelHasActiveBindings` is a composite function that calls both `ChannelHasActiveBoundRules` and `ChannelHasActiveBoundReports` with short-circuit logic. Tests should verify:
1. Returns true when only rules are bound (early return, second call never made)
2. Returns true when only reports are bound
3. Returns false when neither is bound

If only case 3 is tested, the short-circuit optimization could mask a bug where `ChannelHasActiveBoundReports` is never actually called.

---

## Pass 2: Semantic Analysis

### B. Right-Function-Called Verification

All store methods were checked for correct sqlc function delegation. No mismatches found. Each method calls the expected generated query function with correctly-mapped parameters.

### C. TOCTOU Analysis

**BootstrapFirstUserOrg:** Correctly uses `pg_advisory_xact_lock` to serialize concurrent bootstrap attempts. The advisory lock key `0x435654626F6F74` ("CVTboot") is unique. The `COUNT(*) FROM users` check and subsequent org creation are atomic within the locked transaction. **TOCTOU mitigated.**

**InsertAlertEvent:** Uses `ON CONFLICT DO NOTHING RETURNING id` with `ErrNoRows` detection. The UNIQUE constraint `(org_id, rule_id, cve_id, material_hash)` prevents duplicate events. **TOCTOU mitigated.**

**UpsertDelivery:** Uses partial unique index `ON CONFLICT (rule_id, channel_id) WHERE status = 'pending' AND kind = 'alert'` for debounce. The upsert is atomic. **TOCTOU mitigated.**

**RotateSigningSecret:** The SQL `UPDATE` atomically reads `signing_secret` into `signing_secret_secondary` and writes the new primary. **TOCTOU mitigated.**

**SetSSOEmailDomains:** Delete-all-then-insert within a single transaction. No TOCTOU risk as long as the operation is within a single `withOrgTx`. **TOCTOU mitigated.**

### D. Defense-in-Depth / Input Validation at Store Layer

**Finding S5 (security-critical, defense-in-depth):** The store layer performs zero input validation. All validation relies entirely on the API handler layer (huma schema validation) and database constraints. Examples:
- `CreateAlertRule` accepts arbitrary `Logic`, `Conditions` JSON — no store-level check
- `CreateWatchlistItem` trusts `ItemType`, `Ecosystem`, etc. — no store-level guard
- `SetSSOEmailDomains` accepts arbitrary domain strings — no format validation
- `BindChannelToRule` accepts any UUIDs — relies on FK constraints

This is an intentional design decision (YAGNI, single validation layer at API boundary) and the database constraints provide a safety net. However, for a security product, defense-in-depth at the store layer for sensitive operations (SSO domain strings, webhook configs) would reduce the blast radius of a handler-level bypass.

**Verdict:** Noted as a design-level observation, not a bug. The FK constraints and RLS policies provide the critical safety net.

### E. Store-Layer Independence

**Finding AQ3 (assertion quality):** Several tests rely on test helper functions (`mustCreateAlertRule`, `mustCreateNotificationChannel`) that are defined in `helpers_test.go`. These helpers create real database objects, which is correct for integration tests. However, the helpers may mask subtle parameter-passing bugs if they always use the same default values. Tests should occasionally use non-default values for boolean fields like `HasEpssCondition`, `FireOnNonMaterialChanges`, etc.

---

## Findings Summary — Ranked by Severity

### Security-Critical (4)

| ID | Function | Finding |
|----|----------|---------|
| S3 | `LookupAPIKey` | No test verifying expired API keys return nil — the auth hot-path should explicitly test the time-based expiry filtering in the SQL query |
| S4 | `RotateSigningSecret` | No test verifying the old primary becomes the new secondary — if the SQL promotion chain breaks, dual-validation during grace period silently fails |
| S2 | `ListActiveChannelsForFanout` | Signing secret format not validated in test assertions — a truncated secret would pass current tests |
| S5 | Store layer (all) | No input validation at store layer — defense-in-depth gap; all validation relies on API handlers and DB constraints |

### Correctness (8)

| ID | Function | Finding |
|----|----------|---------|
| C1 | `withBypassTx` | Panic recovery path untested — deferred recover+rollback behavior during bypass-RLS tx unverified |
| C2 | `withOrgRawTx` | Panic recovery path untested — deferred recover+rollback during org-scoped tx unverified |
| C3 | `BootstrapFirstUserOrg` | `CreateOrg` failure branch untested in manual transaction — error propagation through 7 branches only covers 2 paths |
| C4 | `BootstrapFirstUserOrg` | `CreateOrgMember` failure after `CreateOrg` success untested — partial state (ownerless org) rollback unverified |
| C5 | `ListCVEs` | 0% coverage — simple sqlc passthrough, low risk, but zero test coverage for any code path |
| C6 | `CompleteJob/FailJob` | No test for non-existent job ID behavior — silently succeeds or returns error? |
| C7 | `UpsertDelivery` | Manual transaction management (not using `withBypassTx`) lacks panic recovery — diverges from standard pattern |
| C8 | `GetCVEDetail` | Child-table query failures (references, packages, CPEs) never individually tested |

### Nice-to-Have (14)

| ID | Function | Finding |
|----|----------|---------|
| N1 | `withBypassTx` | `BeginTx` error branch untested |
| N2 | `withBypassTx` | `SET LOCAL` error branch untested |
| N3 | `withOrgRawTx` | `BeginTx` error branch untested |
| N4 | `withOrgRawTx` | `SET LOCAL` error branch untested |
| N5 | `OrgTx` | `pool.Begin` error branch untested |
| N6 | `WorkerTx` | `pool.Begin` error branch untested |
| N7 | `BootstrapFirstUserOrg` | Advisory lock acquisition error untested |
| N8 | `BootstrapFirstUserOrg` | `tx.Commit()` error branch untested |
| N9 | `UpsertDelivery` | `BeginTx` error branch untested |
| N10 | All auth functions (6) | `fmt.Errorf` wrapping branch at 66.7% untested |
| N11 | All retention functions (10) | Outer `if err != nil` branch at 87.5% untested |
| N12 | `fromNullUUID` | Valid-UUID branch at 66.7% untested |
| N13 | `SetSSOEmailDomains` | Mid-loop insert error untested |
| N14 | `scanCVERow` / `encodeDSLCursor` | Error branches at 75% — unreachable in practice |

### Assertion Quality (3)

| ID | Function | Finding |
|----|----------|---------|
| AQ1 | `CreateAlertRule` tests | Boolean fields (`HasEpssCondition`, `IsEpssOnly`, `FireOnNonMaterialChanges`) not verified in assertions — sqlc parameter position swap would go undetected |
| AQ2 | `ChannelHasActiveBindings` | Composite function short-circuit behavior not tested — may never call `ChannelHasActiveBoundReports` |
| AQ3 | Test helpers generally | Helpers always use default boolean values — non-default paths for boolean fields untested |

---

## Transaction Helper Usage Audit

| Helper | Used By | Count | Correct? |
|--------|---------|-------|----------|
| `withBypassTx` | Auth lookups, worker ops, cross-org queries, retention | ~25 | Yes — all are pre-context or cross-org |
| `withOrgTx` | All org-scoped CRUD (sqlc) | ~35 | Yes — all take orgID |
| `withOrgRawTx` | Dynamic SQL (squirrel) org-scoped | ~5 | Yes — ListAlertRules, ListAlertEvents, ListWatchlists, ListWatchlistItems |
| `OrgTx` | Exposed for pgx native tx (HTTP handlers) | ~1 (external) | Yes — used from outside store |
| `WorkerTx` | Background workers via pgx native tx | ~1 (external) | Yes — used from worker code |
| `s.q.*` directly | ClaimJob, CompleteJob, FailJob, auth functions (no RLS tables) | ~12 | Yes — job_queue and users have no RLS |
| `s.db.*` directly | ExecuteDSLQuery, SearchCVEs | ~2 | Yes — cves is global, no RLS |
| Manual tx | UpsertDelivery, BootstrapFirstUserOrg | ~2 | Correct but documented above |

**No misuse found.** Every function uses the appropriate transaction helper for its context.
