# Phase 8 Coverage Review: Store + Core Packages

**Date:** 2026-03-18
**Reviewer:** Claude (subagent)
**Packages:** internal/store, internal/store/generated, internal/alert, internal/alert/dsl, internal/merge, internal/config, internal/secure, internal/doctor, internal/retention, internal/worker

## Summary Counts

| Severity | Count |
|----------|-------|
| Security-critical | 7 |
| Correctness | 12 |
| Nice-to-have | 14 |
| Assertion quality | 5 |

---

## Package: internal/store (287 funcs, avg 82.3%)

### 0% Coverage (18 functions)

#### S1. LookupAPIKeyByHash -- 0% [security-critical]
**File:** internal/store/apikey.go:112
**Risk:** This function looks up API keys regardless of revocation/expiry status. Used for security event logging (detecting use of revoked keys). While the authentication hot-path (LookupAPIKey) is well-tested at 83.3%, this companion function for the security audit trail has zero coverage. If this function silently fails, revoked-key-usage events will not be logged -- a gap in the security event pipeline.
**Lines:** 18 lines, uses withBypassTx.
**Recommendation:** Correctness test: insert key, revoke it, verify LookupAPIKeyByHash still returns it (vs LookupAPIKey returning nil).

#### S2. GetCVEMaterialHash -- 0% [correctness]
**File:** internal/store/cve.go:32
**Risk:** Returns the material_hash for alert deduplication. Raw SQL query. If this query has a bug, alert events would silently generate duplicate events or miss material changes. However, the merge pipeline tests exercise the hash column thoroughly through GetCVE, and the evaluator tests use material_hash indirectly.
**Lines:** 12 lines.
**Recommendation:** One smoke test calling this after an Ingest to verify the hash value matches.

#### S3. ListCVEs -- 0% [nice-to-have]
**File:** internal/store/cve.go:78
**Risk:** Thin wrapper around sqlc-generated ListCVEs. Only 2 lines. The dynamic SearchCVEs at 91.5% is the primary API path. This function is effectively dead code in the current API surface.
**Recommendation:** Verify if this is actually called anywhere. If not, consider removing.

#### S4. PauseFeed / ResumeFeed / ListFeedFetchLogsPaginated -- 0% [nice-to-have]
**File:** internal/store/feed.go:201-234
**Risk:** Thin wrappers around sqlc queries. Admin feed management operations. Each ~5 lines.
**Recommendation:** Add integration tests when admin feed management API handlers are implemented.

#### S5. Admin store functions -- 0% (12 functions) [correctness]
**Files:** admin_delivery.go (AdminListDeliveries, AdminGetDeliveryByID, AdminRetryDelivery), admin_org.go (AdminUpdateOrgTier, AdminSuspendOrg, AdminUnsuspendOrg, AdminGetOrgUsage), admin_system.go (AdminListAuditEntries), admin_user.go (AdminListUsers, AdminGetUserByID, AdminEnableUser, AdminUnlockUser)
**Risk:** Admin-only operations. AdminSuspendOrg/AdminUnsuspendOrg affect organization access -- a bug could fail to suspend a compromised org. AdminGetOrgUsage aggregates four count queries in one transaction.
**Recommendation:** Priority: AdminSuspendOrg/AdminUnsuspendOrg (security implications).

### Partial Coverage -- Security-Critical

#### S6. withBypassRawTx -- 50% [security-critical]
**File:** internal/store/store.go:73
**Analysis:** Happy path exercised through callers, but error paths (BeginTx, SET LOCAL, panic recovery) untested. The critical behavior (bypass_rls set) IS covered through callers.
**Recommendation:** Nice-to-have -- critical behavior proven via caller tests.

#### S7. withOrgRawTx -- 64.3% [security-critical]
**File:** internal/store/store.go:101
**Analysis:** Same pattern as S6. Critical behavior (SET LOCAL app.org_id) IS tested through TestWithOrgTx_RLSEnforced.

#### S8-S9. OrgTx / WorkerTx -- 77.8% each [security-critical]
**Files:** internal/store/store.go:138, 163
**Analysis:** Commit/rollback tested. Infrastructure error paths (Begin, SET LOCAL failure) uncovered.

### Partial Coverage -- Correctness

#### S10. ListSecurityEvents -- 76.3% [correctness]
**File:** internal/store/security_events.go:99
**Analysis:** Raw SQL with 8 nullable parameters. Missing: filter by severity, date range, cursor pagination tests.

#### S11. BootstrapFirstUserOrg -- 76.2% [correctness]
**File:** internal/store/org.go:101
**Analysis:** Multi-step transaction. Missing error path mid-transaction.

#### S13. SearchCVEs -- 91.5% [correctness]
**File:** internal/store/cve.go:124
**Analysis:** 15 optional filters. Missing: EPSS range and ExploitAvail filter tests.

### Partial Coverage -- MFA Store

#### S14. VerifyAndUpdateTOTPStep -- 80% [security-critical]
**File:** internal/store/mfa.go:91
**Analysis:** FOR UPDATE anti-replay logic IS tested. Error path is standard wrapping.

#### S15. VerifyRecoveryCode -- 78.3% [security-critical]
**File:** internal/store/mfa.go:239
**Analysis:** Likely missing wrong-code path or mark-used error path.

#### S16. VerifyEmailOTPChallenge -- 77.3% [security-critical]
**File:** internal/store/mfa.go:387
**Analysis:** Likely missing exhausted-attempts path.

---

## Package: internal/store/generated (274 funcs, avg 84.7%)

### 0% Coverage -- Notable

#### G1. InsertAffectedCPE -- 0% [correctness]
**File:** internal/store/generated/cves.sql.go:377
**Risk:** Merge pipeline calls this for CPE insertion. No test provides CPE data. InsertAffectedPackage (same pattern) IS at 100%.

#### G2. UpsertEPSSStaging -- 0% [correctness]
**File:** internal/store/generated/cves.sql.go:725
**Risk:** EPSS staging for CVEs that do not exist yet. If staging INSERT has a bug, EPSS scores for new CVEs would be silently lost.

#### G3. GetActiveEmailOTPChallenge / GetUnusedRecoveryCodeByHash -- 0% [correctness]
**Analysis:** ForUpdate variants at 100%. Non-ForUpdate versions may be dead code.

#### G4. ListSecurityEvents (generated) -- 0% [correctness]
**Analysis:** Dead code -- store uses raw SQL instead of the sqlc-generated version.

### 73.3% Cluster
Many generated list functions at 73.3% -- standard sqlc row-iteration pattern, uncovered branch is rows.Err() (mid-iteration connection drop). Not a concern.

---

## Package: internal/alert (24 funcs, avg 84.7%)

#### A1. EvaluateActivation -- 72.5% [correctness]
Missing: compilation error path, mid-batch error, concurrent status change.

#### A2. bypassTx -- 58.3% [correctness]
Missing: statementTimeoutMS > 0 path.

#### A3. runStatus -- 50% [nice-to-have]
Trivial 3-way switch. Missing "partial" branch.

---

## Package: internal/alert/dsl (22 funcs, avg 93.9%)

#### D1. conditionToSQL -- 80% [correctness]
Missing: default error branch for unknown field categories.

#### D2. textSQL -- 77.8% [correctness]
Missing: likely "ends_with" operator.

#### D4. affectedPackageSQL -- 81.8% [correctness]
Missing: starts_with/ends_with for package names.

---

## Package: internal/merge (22 funcs, avg 94.1%)

#### M1. Ingest -- 69.1% [correctness]
260-line function, 10 steps. Critical paths (hash, PK migration, tombstone, EPSS staging) all have dedicated tests. 69.1% expected for an orchestration function of this size.

#### M2-M3. migrateCVEPKRename/Merge -- 71.4% each [correctness]
Happy paths tested. Error branches in loops uncovered.

---

## Package: internal/config (12 funcs, avg 87.3%)

#### C1. StartSIGHUPHandler (Windows) -- 0% [nice-to-have]
No-op stub. Skip.

#### C2. LoadFromConfig -- 80% [correctness]
Missing: invalid hex SSO key warning path.

---

## Package: internal/secure (19 funcs, avg 88.7%)

#### SE1. formatCEF -- 61.9% [correctness]
Missing: CEF extension branches for UserID, OrgID, ActorEmail.

#### SE3. EventWriter.Write -- 78.9% [security-critical]
Critical behaviors (rate limiting, async, race safety) well-tested. Missing: panic recovery, syslog forward error.

---

## Package: internal/doctor (29 funcs, avg 87.9%)

#### DR1. RLSCheck.Run -- 48.0% [security-critical]
Failure-detection paths untested -- misconfigured RLS will not be caught.

#### DR2. EncryptionSentinelCheck.Run -- 50.0% [security-critical]
Dual-key rotation fallback likely untested.

---

## Package: internal/retention (5 funcs, avg 97.6%)
Well-covered. Minor gaps in disabled path and error propagation.

---

## Package: internal/worker (10 funcs, avg 72.3%)

#### W1-W2. RegisterPeriodic + runPeriodic -- 0% [correctness]
Periodic task system (batch evaluator, EPSS, retention) completely untested.

#### W3. runStaleRecovery -- 53.8% [correctness]
Error path and stuck-job recovery partially covered.

---

## Assertion Quality Audit

### AQ1. RLS test -- shallow [assertion-quality]
Tests only watchlists table. Does not verify all org-scoped tables have RLS.

### AQ2. EventWriter -- missing syslog assertion [assertion-quality]
Never verifies syslog.Send is actually called with a real or mock writer.

### AQ3. Alert evaluator -- GOOD [assertion-quality-positive]
Thorough: event count, match_state, suppress_delivery, status transitions, dedup, resolution, regex, candidate cap.

### AQ4. Merge pipeline -- GOOD [assertion-quality-positive]
19 tests, assertions on specific column values not just "no error".

### AQ5. Store transactions -- adequate [assertion-quality]
Behavioral assertions (RLS row visibility) are stronger than variable-value checks.

---

## Semantic Analysis: Defense-in-Depth

- **SEM1. Store org_id enforcement:** PASS -- every org-scoped method uses withOrgTx/withOrgRawTx
- **SEM2. LookupAPIKey bypass:** PASS -- correctly uses withBypassTx for auth hot-path
- **SEM3. Merge advisory lock:** PASS -- concurrent write test proves serialization
- **SEM4. Candidate cap fail-closed:** PASS -- 5002 CVEs test proves partial=true with 0 events

---

## Production Bug Candidates

### BUG1: InsertAffectedCPE at 0%
Merge pipeline step 8 calls this but no test provides CPE data. sqlc validates against schema at codegen time, so column mismatches are unlikely. But runtime behavior (constraint violations, NULL handling) is unvalidated.

### BUG2: UpsertEPSSStaging at 0%
The "CVE does not exist yet" branch of the EPSS handler may be untested. If staging INSERT has a bug, EPSS scores for new CVEs are silently lost.

---

## Top 5 Findings

1. **LookupAPIKeyByHash (0%)**: Security audit function for revoked-key detection has no tests.
2. **RLSCheck doctor check (48%)**: Failure-detection paths untested -- misconfigured RLS will not be caught.
3. **RegisterPeriodic + runPeriodic (0%)**: Worker periodic task system (runs batch/EPSS/retention) untested.
4. **InsertAffectedCPE + UpsertEPSSStaging (0%)**: Critical data pipeline functions never runtime-validated.
5. **EncryptionSentinelCheck (50%)**: Dual-key rotation detection likely untested.
