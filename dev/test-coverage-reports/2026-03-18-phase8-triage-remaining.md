# Phase 8 Coverage-Guided Triage: Remaining Packages

Agent scope: All packages EXCEPT internal/store and internal/api.
Date: 2026-03-18

---

## Coverage Baseline

| Package | Key Functions | Approx Coverage | Notes |
|---------|--------------|-----------------|-------|
| internal/secure | 19 | ~85% | Rate limiting and writer well-covered; syslog CEF partially covered |
| internal/config | 12 | ~85% | Reload and holder well-tested; SIGHUP handler 0% (Windows no-op) |
| internal/auth | 12 | ~90% | JWT dual-key exhaustively tested; Issue sign-error branches uncovered |
| internal/crypto | 4 | ~90% | DecryptWithFallback 100%; Encrypt rand.Read error uncovered |
| internal/doctor | 29 | ~75% | Many check Run() methods partially covered |
| internal/feed | 85 | ~85% | Good per-adapter coverage; some error/edge paths uncovered |
| internal/ingest | 21 | ~75% | Core handler 87%; Scheduler Start/AddEntries 0% |
| internal/merge | 22 | ~88% | Ingest pipeline 69%; resolve 92.5% |
| internal/notify | 46 | ~80% | Render, webhook, worker well-covered; digest partially covered |
| internal/alert | 46 | ~82% | DSL compiler partially covered; evaluator bypassTx 58% |
| internal/retention | 5 | ~97% | Very well covered |
| internal/worker | 10 | ~75% | Core pool 95%+; RegisterPeriodic/runPeriodic 0% |
| internal/ai | 13 | ~75% | Mock/schema 100%; real Gemini client 0% (expected) |
| internal/metrics | 3 | 100% | Fully covered |
| internal/log | 3 | 100% | Fully covered |
| internal/audit | 9 | ~85% | Writer and redact well-covered |
| internal/tier | 4 | 100% | Fully covered |
| internal/dbutil | 2 | 100% | Fully covered |

---

## Security-Critical Gaps

### S1. config.StartSIGHUPHandler (Windows) at 0% -- coverage
- **File:** internal/config/sighup_windows.go:6
- **Risk:** Low (no-op stub for Windows). The Unix variant calls ReloadConfig which IS tested.
- **Severity:** Nice-to-have

### S2. secure.EventWriter.Write -- syslog forwarding path partially covered (78.9%) -- coverage
- **File:** internal/secure/writer.go:57
- **Gap:** The syslog forwarding branch inside the async goroutine is not truly exercised with a real syslog writer. All tests use SetSyslog(nil).
- **Severity:** Security-critical. If syslog forwarding silently fails, SIEM receives no events.

### S3. secure.EventWriter.Stop at 60% -- coverage
- **File:** internal/secure/writer.go:112
- **Gap:** The sw.Close() error path (line 117-118) is not covered.
- **Severity:** Correctness

### S4. secure.cefSeverity at 50% -- coverage
- **File:** internal/secure/syslog.go:160
- **Gap:** SeverityWarning branch not independently verified for correct numeric value.
- **Severity:** Correctness

### S5. secure.formatCEF at 61.9% -- coverage
- **File:** internal/secure/syslog.go:171
- **Gap:** UserID and OrgID branches not exercised in CEF format test.
- **Severity:** Correctness

### S6. crypto.Encrypt at 70% -- coverage
- **File:** internal/crypto/aes.go:46
- **Severity:** Nice-to-have

### S7. auth Issue functions all at 85.7% -- coverage
- **File:** internal/auth/jwt.go:28, 94, 166, 231
- **Severity:** Nice-to-have

### S8. auth.ParseEnrollmentToken at 84.6% -- coverage
- **File:** internal/auth/jwt.go:253
- **Gap:** No TestParseEnrollmentToken_UnknownKeyRejects test. Dual-key fallback failure path untested.
- **Severity:** Security-critical. Enrollment tokens carry encrypted TOTP secrets.

### S9-S12. Other auth/config gaps (nice-to-have or correctness)
- auth.HashPassword 83.3% -- rand.Read error (nice-to-have)
- auth.GenerateAPIKey 83.3% -- rand.Read error (nice-to-have)
- config.LoadFromConfig 80% -- SSOEncryptionKeyPrevious error path (correctness)
- config.LoadFromSecretsFile 92.8% -- scanner.Err() path (nice-to-have)

---

## Correctness Gaps

### C1. alert.evaluator.bypassTx at 58.3% -- internal/alert/evaluator.go:544
### C2. alert.evaluator.runStatus at 50% -- internal/alert/evaluator.go:688
### C3. alert.evaluator.writeCursor at 71.4% -- internal/alert/evaluator.go:665
### C4. alert.evaluator.readCursor at 80% -- internal/alert/evaluator.go:644
### C5. alert.evaluator.EvaluateActivation at 72.5% -- internal/alert/evaluator.go:223
### C6. alert.dsl.conditionToSQL at 80% -- internal/alert/dsl/compiler.go:141
### C7. alert.dsl.numericSQL at 81.8% -- internal/alert/dsl/compiler.go:195
### C8. alert.dsl.textSQL at 77.8% -- internal/alert/dsl/compiler.go:248
### C9. alert.dsl affected functions at 75-87.5% -- internal/alert/dsl/compiler.go:266, 277, 318
### C10. alert.PostFilterField at 66.7% -- internal/alert/evaluator.go:39
### C11. ingest.NewAdapter at 30% -- internal/ingest/feeds.go:95
### C12. ingest.Scheduler.AddEntries at 0% / Start at 0% -- internal/ingest/scheduler.go:96, 102
### C13. ingest.HandlerWithAlerts / HandlerWithFactoryAndAlerts at 0% -- internal/ingest/handler.go:62, 68
### C14. merge.Ingest at 69.1% -- internal/merge/pipeline.go:38
### C15. merge PK migration functions at 71-85% -- internal/merge/pipeline.go:375, 392, 424
### C16. notify.RenderMFAOTP at 0% -- internal/notify/render.go:133
### C17. notify digest functions at 55-57% -- internal/notify/digest.go:87, 178
### C18. notify.worker recovery functions at 50-66% -- internal/notify/worker.go:404, 410
### C19. notify.worker.exhaust at 50% (nice-to-have) -- internal/notify/worker.go:367
### C20. notify.Unwrap at 0% (nice-to-have) -- internal/notify/worker.go:344
### C21. worker.RegisterPeriodic at 0% / runPeriodic at 0% -- internal/worker/pool.go:81, 244
### C22. worker.runStaleRecovery at 53.8% -- internal/worker/pool.go:273
### C23. doctor.StandardChecks at 57.1% -- internal/doctor/checks.go:454
### C24. Doctor check Run() methods at 48-75% -- internal/doctor/checks.go
### C25. feed.epss.applyRow at 0% -- internal/feed/epss/adapter.go:250
### C26. feed.generic.nextPage at 37.5% -- internal/feed/generic/adapter.go:337
### C27. feed.generic.applyAuth at 73.7% -- internal/feed/generic/adapter.go:497
### C28. notify.EmailSend at 72% -- internal/notify/email.go:26
### C29. notify.BuildSafeClient at 83.3% (nice-to-have) -- internal/notify/client.go:15

---

## Assertion Quality Issues

### A1. secure.writer_test.TestSecurityEventWriter_SetSyslogRaceSafe -- assertion
- **File:** internal/secure/writer_test.go:106
- **Issue:** Execution-only test with no assertions on syslog forwarding behavior.

### A2. Syslog CEF test does not verify numeric severity value -- assertion
- **File:** internal/secure/syslog_test.go:106
- **Issue:** Substring match only. Bug in cefSeverity() would not be caught.

### A3. config.reloadable_test.TestLoadFromConfig_SSOKeyDecoding -- assertion
- **File:** internal/config/reloadable_test.go:239
- **Issue:** Only tests SSO primary key decoding, not previous key.

---

## What is Well-Covered

- **JWT dual-key rotation (auth package):** 35+ tests, all 4 token types, dual-key, alg confusion, alg:none.
- **Config hot-reload:** ReloadConfig 100% with success, failure, panic, missing file, rescan.
- **Security event rate limiting:** 100% Allow and eviction coverage with injectable clocks.
- **Feed adapter parsing:** Most adapters 85%+ (NVD 97.3%, MSRC 94.8%, Red Hat 94.4%).
- **Retention runner:** 93-100% across all functions.

---

## Production Bugs Discovered

None confirmed. Two patterns warrant investigation:

1. **Syslog forwarding untested in integration:** EventWriter.Write test never exercises syslog send path -- all tests use SetSyslog(nil).

2. **RenderMFAOTP at 0%:** If the MFA OTP template has a syntax error, email OTP silently fails.

---

## Gap Context Summary

| Category | Count | Action |
|----------|-------|--------|
| Security-critical | 2 | S2 (syslog in Write goroutine), S8 (enrollment token unknown key) |
| Correctness | 29 | C1-C29 |
| Nice-to-have | 8 | S1, S6, S7, S9, S10, S12, C19, C20 |
| Assertion quality | 3 | A1-A3 |
| **Total** | **42** | |

---

## Key Observations

### Cross-Cutting Patterns

1. **rand.Read error branches systematically uncovered** across HashPassword, GenerateAPIKey, Encrypt. Low priority.

2. **JWT Issue* functions have identical 85.7% pattern** -- same uncovered SignedString error in all four. One gap, not four.

3. **Worker/scheduler goroutine loops at 0%** -- blocking loops hard to test. Core logic IS tested.

4. **Doctor check Run() methods systematically 48-75%** -- healthy path tested, degraded/failed not. False-healthy is worse than no check.

5. **CEF syslog assertions are substring-based** -- do not verify numeric severity values or full CEF structure.

6. **Alert DSL compiler operator variants partially covered** -- each operator is a separate code path. Testing one does not prove the others.
