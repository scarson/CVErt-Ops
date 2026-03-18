# Phase 8 Test Coverage Review: Feeds, Support Packages, CLI

**Date:** 2026-03-18
**Scope:** internal/feed/*, internal/notify, internal/ingest, internal/log, internal/audit, internal/dbutil, internal/metrics, internal/tier, internal/testutil, cmd/cvert-ops

---

## Summary Counts

| Severity | Count |
|----------|-------|
| Security-critical | 3 |
| Correctness | 9 |
| Nice-to-have | 8 |
| Assertion quality | 5 |

---

## Pass 1: Coverage-Guided Triage

### Package: internal/feed/generic (avg 86.7%)

#### 0% functions: None

#### Partial coverage (<80%):

| Function | Coverage | Uncovered Branches |
|----------|----------|--------------------|
| fetchJSONStream | 72.5% | Error paths: non-object opening token, non-string key token, array open not [, decode record error, decode cursor error, skip key error |
| nextPage | 37.5% | Offset and cursor cases exercised via Fetch but function-level metric is low because cursor-with-nested-path uses buffered path |
| applyAuth | 73.7% | The header auth type with empty HeaderValueEnv uncovered. Basic auth with both user AND pass empty is not tested |
| fetchCSAF | 72.2% | Error paths: rate limiter error, request build error, HTTP error status, CSAF parse error |
| csafToPatches | 83.7% | CVSSv4 score extraction in CSAF docs (no test provides cvss_v4 block), empty CVE field skip |
| ParseConfig | 75.0% | YAML unmarshal error path |
| LoadDir | 80.8% | ReadFile error within loop, ParseConfig failure within loop |

#### 80%+ partial:

| Function | Coverage | Uncovered Branch |
|----------|----------|------------------|
| fetchJSON | 88.5% | Cursor unmarshal error, rate limiter wait error |
| fetchJSONBuffered | 83.3% | ReadAll body error path |
| buildURL | 91.7% | Cursor pagination with existing query string (URL already contains ?) |
| nextPageFromStream | 94.1% | Nested cursor path with dots safety net |
| mapRecord | 87.0% | cvss_v4_score, cvss_v4_vector field mapping untested for JSON format |
| validateCron | 87.5% | Invalid character detection in field loop |
| cronToInterval | 93.8% | Fixed minute+hour pattern (last branch before default) |

#### 100% functions: NewAdapter, Fetch, Validate, NewLoader, Rescan, ScheduleEntries, AdapterFactory

### Package: internal/feed/epss

| Function | Coverage | Notes |
|----------|----------|-------|
| applyRow | 0.0% | SECURITY-CRITICAL: Two-statement EPSS pattern with advisory locking. Requires real sql.DB. Need to verify integration test actually exercises this. |
| Apply | 74.2% | Uncovered: CSV parsing error mid-stream, context cancellation, batch logging |

### Package: internal/feed/* (other adapters) -- all 80%+ average

Key partial: ghsa/Fetch 85.2%, kev/parseKEV 77.8%, mitre/New 66.7%, msrc/New 66.7%, nvd/parseNVDResponse 75.6%, osv/parseEntry 75.0%, redhat/New 66.7%, redhat/parseListResponse 75.0%

### Package: internal/notify (avg 85.1%)

#### 0% functions: RenderMFAOTP (low risk), Unwrap (trivial)

#### Partial coverage (<80%):

| Function | Coverage | Uncovered Branches |
|----------|----------|--------------------|
| runDigest | 57.1% | ClaimDueReports error path, executeDigestReport error path |
| advanceReport | 55.6% | Error from advanceNextRunAt (invalid timezone), skip-forward loop |
| Start | 70.8% | Ticker select cases tested individually via RunOnce methods |
| EmailSend | 72.0% | TLS mandatory path, SMTP auth path |
| Fanout | 76.9% | JSON marshal error (practically impossible) |
| renderPair | 72.7% | Template execution error paths |
| runStuckReset | 50.0% | Error from ResetStuckDeliveries |
| exhaust | 50.0% | Error from ExhaustDelivery |
| runRecovery | 66.7% | OrphanedAlertEvents error path |
| scheduleRetention | 73.3% | HasPendingOrRunningJob error, EnqueueJob error |
| executeDigestReport | 78.8% | DigestCVEs error, ListActiveChannelsForDigest error |

#### 80%+ partial:

| Function | Coverage | Uncovered |
|----------|----------|-----------|
| deliver | 81.4% | CompleteDelivery DB error after successful send |
| runClaim | 82.4% | ClaimPendingDeliveries error |
| BuildSafeClient | 83.3% | Transport type check (defensive dead code) |
| deliverEmail | 83.3% | Render template error, unsupported kind default |
| ComputeNextRunAt | 90.9% | Candidate exactly equal to now |
| buildSnapshot | 89.5% | GetCVESnapshot error path |
| Send (webhook) | 95.8% | Request build error (invalid URL) |

### Package: internal/ingest (avg 75.9%)

0% functions: backoffDuration, HandlerWithAlerts, HandlerWithFactory, HandlerWithFactoryAndAlerts -- all low risk one-line delegations or pure math.

### Package: internal/audit (avg 93.9%)

Partial: Log 82.4% (panic recovery, GetUserByID error), buildStoreEntry 70.0% (marshalState error), marshalState 92.3%

### Package: cmd/cvert-ops (many at 0%)

Most 0% functions are expected (CLI wiring requiring full environment). Notable gaps: runDoctor 0%, quotaGetCmd/ListCmd/DeleteCmd 0%, statusMarker/countByStatus 0%. Partial: autoMigrate 46.2%, rotateEncryptionKeys 73.7%, parseHexKey 90.0%.

### 100% packages: internal/log, internal/metrics (db.go), internal/tier, internal/dbutil

---

## Pass 2: Semantic Analysis

### A. Generic Feed Adapter

**SC1 - SSRF Protection [security-critical]:** NewAdapter(cfg, nil) creates bare http.Client without SSRF protection. Need to verify main.go always passes safeurl-wrapped client.

**C1 - Config Validation [correctness]:** Validate() does not check that cursor_param/cursor_path are set when pagination.type == cursor, or page_param for offset. A misconfigured cursor feed could loop infinitely.

**C5 - CVSSv4 [correctness]:** No test covers CVSSv4 extraction in CSAF format or JSON gjson mapping.

### B. Notify Package

**F5 - Webhook delivery safety [verified correct]:** deliverWebhook does NOT hold open DB tx during HTTP call. Pattern: claim-commit-deliver-update. Matches PLAN.md.

**SC2 - HMAC with empty secret [security-critical]:** Send() computes HMAC with empty key if SigningSecret is empty. Signature header sent but provides no security.

**F6 - Fan-out error handling [verified correct]:** Per-channel error logging without abort. Architecturally correct.

### C. Ingest Package

Scheduler correctness verified. No TOCTOU race (DB lock_key dedup). Backoff-before-paused ordering is intentional (tested).

### D. CLI Commands

**C4 - Key rotation [correctness]:** rotateEncryptionKeys decrypt/encrypt error paths uncovered at 73.7%. Transaction rollback is correct but untested.

**C3 - Doctor CLI [correctness]:** runDoctor 0% -- StandardChecksConfig field mapping untested.

### E. Audit Package

Redaction quality good. Non-blocking guarantee tested. context.WithoutCancel + recover() pattern correct.

---

## Assertion Quality Issues

1. **AQ1:** TestAdapter_URLUnreachable -- error message not verified, only assert.Error
2. **AQ2:** TestAdapter_NonJSONResponse -- error type not checked
3. **AQ3:** TestWorker_GracefulShutdown -- does not test in-flight delivery survival
4. **AQ4:** TestBuildSafeClient_ReturnsValidClient -- does not verify MaxConnsPerHost=50
5. **AQ5:** RenderMFAOTP completely untested (only Render* without a test)

---

## Security-Critical Findings

### SC1: Generic feed adapter SSRF via nil client
**File:** internal/feed/generic/adapter.go:56-58
**Issue:** NewAdapter(cfg, nil) creates bare http.Client without SSRF protection. Admin-configured URLs could target internal infrastructure.
**Recommendation:** Verify main.go always passes safeurl client. Consider rejecting nil client.

### SC2: Webhook HMAC with empty signing secret
**File:** internal/notify/webhook.go:57
**Issue:** Empty SigningSecret still computes/sends HMAC with empty key. Provides false sense of security.
**Recommendation:** Validate SigningSecret is non-empty in Send, or log warning.

### SC3: EPSS applyRow at 0% function-level coverage
**File:** internal/feed/epss/adapter.go:250
**Issue:** Critical advisory lock + two-statement pattern reports 0% coverage. May be a reporting artifact but needs verification.
**Recommendation:** Add targeted integration test confirming both statements execute within advisory lock.

---

## Correctness Findings

### C1: Missing pagination config sub-field validation
**File:** internal/feed/generic/config.go:70-132
**Issue:** cursor_param/cursor_path not validated as required for cursor pagination type. A config with type: cursor but empty cursor_param could cause infinite refetching of page 1.

### C2: quotaGetCmd, quotaListCmd, quotaDeleteCmd untested (0%)
**File:** cmd/cvert-ops/quota.go:64-170

### C3: doctor CLI wiring untested (0%)
**File:** cmd/cvert-ops/doctor.go:23-69

### C4: rotateEncryptionKeys error branches uncovered (73.7%)
**File:** cmd/cvert-ops/rotate.go:87-156
**Issue:** Decrypt failure, encrypt failure, RowsAffected!=1 paths uncovered.

### C5: CSAF CVSSv4 extraction untested
**File:** internal/feed/generic/adapter.go:596-622

### C6: executeDigestReport channel iteration error path uncovered
**File:** internal/notify/digest.go:107-175

### C7: parseHexKey empty string path uncovered
**File:** cmd/cvert-ops/rotate.go:66-80

### C8: validateFeature valid path uncovered (66.7%)
**File:** cmd/cvert-ops/quota.go:180-185

### C9: advanceReport timezone error path uncovered (55.6%)
**File:** internal/notify/digest.go:178-192

---

## Nice-to-have Findings

### N1: adapter.New nil-client paths at 66.7% for mitre, msrc, redhat
### N2: DownloadToTemp at 66.7% -- OS-level error paths
### N3: WrapClientWithUA at 90.0% -- nil-client path
### N4: RenderMFAOTP at 0% -- same pattern as 5 other tested render functions
### N5: exhaust at 50%, runStuckReset at 50% -- one-line store calls
### N6: Worker.Start at 70.8% -- ticker branches tested individually
### N7: BuildSafeClient MaxConnsPerHost=50 not asserted
### N8: autoMigrate advisory lock paths at 46.2%

---

## Production Bug Candidates

### PB1: Generic feed cursor pagination infinite fetch
A config with pagination.type: cursor but empty cursor_param causes buildURL to return the base URL unchanged every page. If cursor_path finds a non-empty value in the response, LastPage is false, and the adapter fetches the same page infinitely. The empty-patches safety net only fires when patches are empty. This is a config validation gap (C1).

No other production bugs found. Webhook delivery, HMAC signing, EPSS advisory locking, and notification fan-out patterns are correct.

---

## Recommendations (Priority Order)

1. Verify generic feed adapter client injection in main.go (SC1)
2. Add pagination config sub-field validation (C1/PB1)
3. Test EPSS applyRow advisory lock pattern (SC3)
4. Add CSAF CVSSv4 test case (C5)
5. Add quotaGet/List/Delete tests (C2)
6. Add doctor CLI wiring test (C3)
7. Test parseHexKey empty string (C7)
8. Test rotateEncryptionKeys decrypt failure rollback (C4)
9. Add RenderMFAOTP basic test (AQ5)
10. Strengthen error message assertions in generic adapter tests (AQ1, AQ2)
