# Phase 4 Test Coverage Review — CLI, Config, Metrics & Wire-Up

**Date:** 2026-03-03
**Scope:** `cmd/cvert-ops/quota.go`, `cmd/cvert-ops/main.go` (Phase 4 additions), `internal/config/config.go` (AI fields), `internal/metrics/ai.go`

---

## 1. `cmd/cvert-ops/quota.go` + `cmd/cvert-ops/quota_test.go`

### 1a. `quotaCmd()` (line 15)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Creates parent cobra command with 4 subcommands | 15-22 | GAP -- no test verifies the parent command registers all 4 subcommands | nice-to-have |

### 1b. `quotaSetCmd()` RunE (lines 24-62)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Invalid org ID (uuid.Parse fails) | 32-34 | GAP -- no test with a malformed UUID | correctness |
| Invalid feature name (validateFeature fails) | 36-38 | Covered (`TestQuotaCmd_SetInvalidFeature`) |  |
| config.Load fails | 40-43 | GAP -- no test (requires env manipulation) | nice-to-have |
| newPool fails (DB unreachable) | 44-47 | GAP -- no test | nice-to-have |
| s.SetAIQuotaOverride succeeds | 51 | Covered (integration -- `TestQuotaCmd_SetAndGet` calls store directly) |  |
| s.SetAIQuotaOverride DB error | 51 | GAP -- no test injects a DB error | correctness |
| Required flags missing (--org, --feature, --limit) | 58-60 | GAP -- no test verifies cobra rejects missing required flags | correctness |

### 1c. `quotaGetCmd()` RunE (lines 64-105)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Invalid org ID | 72-74 | GAP -- no test | correctness |
| config.Load fails | 76-78 | GAP -- no test | nice-to-have |
| newPool fails | 80-83 | GAP -- no test | nice-to-have |
| ListAIQuotaOverridesForOrg DB error | 87-89 | GAP -- no test | correctness |
| No overrides exist (empty result, prints message) | 91-94 | GAP -- no test verifies the "No overrides set" output path via CLI | correctness |
| One or more overrides exist (prints formatted output) | 95-97 | Covered (integration -- `TestQuotaCmd_SetAndGet` calls ListAIQuotaOverridesForOrg and asserts) |  |
| Required flag --org missing | 103 | GAP -- no test | correctness |

**Note:** `TestQuotaCmd_SetAndGet` calls store methods directly, not through the cobra command. This tests the store layer, not the CLI command wiring. The cobra command itself (argument parsing, flag validation, output formatting) has no dedicated test.

### 1d. `quotaListCmd()` RunE (lines 107-137)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| config.Load fails | 112-114 | GAP -- no test | nice-to-have |
| newPool fails | 116-119 | GAP -- no test | nice-to-have |
| ListAIQuotaOverrides DB error | 123-125 | GAP -- no test | correctness |
| No overrides exist (prints "No overrides configured.") | 127-130 | GAP -- no test | correctness |
| Overrides exist (formatted output with org/feature/limit) | 131-133 | GAP -- no test exercises this path through the CLI | correctness |

### 1e. `quotaDeleteCmd()` RunE (lines 139-171)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Invalid org ID | 147-149 | GAP -- no test | correctness |
| config.Load fails | 151-153 | GAP -- no test | nice-to-have |
| newPool fails | 155-158 | GAP -- no test | nice-to-have |
| s.DeleteAIQuotaOverride succeeds | 162 | Covered (integration -- `TestQuotaCmd_Delete` calls store directly) |  |
| s.DeleteAIQuotaOverride DB error | 162 | GAP -- no test | correctness |
| Required flags --org, --feature missing | 168-169 | GAP -- no test | correctness |

### 1f. `validateFeature()` (lines 180-185)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Valid feature "nl_search" | 181 | Covered (integration -- `TestQuotaCmd_SetAndGet` uses "nl_search") |  |
| Valid feature "summarize" | 181 | Covered (integration -- `TestQuotaCmd_Delete` uses "summarize") |  |
| Invalid feature name | 182-183 | Covered (`TestQuotaCmd_SetInvalidFeature`) |  |
| Empty string | 182-183 | GAP -- no explicit test for empty string | nice-to-have |

---

## 2. `cmd/cvert-ops/main.go` -- Phase 4 Additions

### 2a. `runServe()` -- LLM Client Initialization (lines 120-130)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| `GeminiMock=true` -> `ai.NewMockClient()` | 121-123 | GAP -- no test verifies mock client is used when GeminiMock=true | correctness |
| `GeminiMock=false` + `GeminiAPIKey != ""` -> `ai.NewGeminiClient()` | 124-129 | GAP -- no test | correctness |
| `GeminiMock=false` + `GeminiAPIKey == ""` -> llm remains nil | 120-130 | GAP -- no test verifies llm=nil path (AI endpoints return 503) | correctness |
| `ai.NewGeminiClient` returns error | 126-128 | GAP -- no test | correctness |

### 2b. `runServe()` -- AI Dependency Wiring (lines 144-146)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| `llm != nil` -> `apiSrv.SetAIDeps(llm)` called | 144-146 | GAP -- no test verifies AI deps are wired | correctness |
| `llm == nil` -> `SetAIDeps` not called, AI endpoints return 503 | 144 | GAP -- no test | correctness |

### 2c. `retentionHandler()` -- AI Log Retention (lines 295-311)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| `AILogRetentionDays` passed to retention.Config | 304 | Covered (integration -- `TestRunner_AICleanup` in `internal/retention/runner_test.go`) |  |

### 2d. `validateConfig()` (lines 479-487)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| JWT_SECRET < 32 bytes -> error | 480-481 | GAP -- no unit test | security-critical |
| JWT_SECRET >= 32 bytes -> passes | 480 | GAP -- no unit test | security-critical |
| Non-development + ExternalURL not https -> error | 483-484 | GAP -- no unit test | security-critical |
| Non-development + ExternalURL is https -> passes | 483 | GAP -- no unit test | security-critical |
| Development mode + ExternalURL http -> passes (IsDevelopment bypass) | 483 | GAP -- no unit test | security-critical |

### 2e. `newLogger()` (lines 494-510)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| LogLevel "debug" -> slog.LevelDebug | 498 | GAP -- no test | nice-to-have |
| LogLevel "warn" -> slog.LevelWarn | 500 | GAP -- no test | nice-to-have |
| LogLevel "error" -> slog.LevelError | 502 | GAP -- no test | nice-to-have |
| LogLevel "info" (default, no match) -> slog.LevelInfo | 496 | GAP -- no test | nice-to-have |
| LogFormat "text" -> TextHandler | 507 | GAP -- no test | nice-to-have |
| IsDevelopment() -> TextHandler (overrides json) | 506-507 | GAP -- no test | nice-to-have |
| LogFormat "json" (non-dev) -> JSONHandler | 509 | GAP -- no test | nice-to-have |

### 2f. `newPool()` (lines 394-475)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| ParseConfig fails | 396-398 | GAP -- no test | nice-to-have |
| DBQueryExecMode == "simple_protocol" branch | 401-403 | GAP -- no test | nice-to-have |
| Retry loop: successful on first attempt | 418-425 | GAP -- no test | nice-to-have |
| Retry loop: fails then succeeds | 418-438 | GAP -- no test | nice-to-have |
| Retry loop: ctx cancelled during retry | 433-436 | GAP -- no test | correctness |
| Retry loop: all 10 attempts fail | 440-442 | GAP -- no test | correctness |
| Ping succeeds after NewWithConfig | 421 | GAP -- no test | nice-to-have |
| Ping fails, pool closed, retry | 421-424 | GAP -- no test | nice-to-have |
| max_connections warning: DBMaxConns > 80% of pg limit | 450-454 | GAP -- no test | nice-to-have |
| Schema version mismatch warning | 467-471 | GAP -- no test | nice-to-have |
| Schema version matches | 467 | GAP -- no test | nice-to-have |

---

## 3. `internal/config/config.go` -- AI-Related Fields

**No test file exists for `internal/config/`.**

### 3a. `Load()` (lines 120-126)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Successful parse with defaults | 121-125 | GAP -- no test verifies default values | correctness |
| Missing required field (DATABASE_URL, JWT_SECRET) -> error | 122-123 | GAP -- no test | security-critical |
| Parse error (invalid type for field) | 122-123 | GAP -- no test | correctness |

### 3b. AI Config Fields -- Default Values (lines 69-80)

| Config Field | Default | Test Status | Severity |
|-------------|---------|-------------|----------|
| `GeminiTimeout` = 30s | line 69 | GAP -- no test verifies default | correctness |
| `AIQuotaEnabled` = true | line 70 | GAP -- no test verifies default | security-critical |
| `AINLSearchLimitFree` = 10 | line 71 | GAP -- no test verifies default | correctness |
| `AINLSearchLimitPro` = 100 | line 72 | GAP -- no test | correctness |
| `AINLSearchLimitEnterprise` = 1000 | line 73 | GAP -- no test | correctness |
| `AISummarizeLimitFree` = 5 | line 74 | GAP -- no test | correctness |
| `AISummarizeLimitPro` = 50 | line 75 | GAP -- no test | correctness |
| `AISummarizeLimitEnterprise` = 500 | line 76 | GAP -- no test | correctness |
| `AICacheNLSearchTTL` = 1h | line 77 | GAP -- no test | correctness |
| `AICacheSummarizeTTL` = 24h | line 78 | GAP -- no test | correctness |
| `AILogRetentionDays` = 90 | line 79 | GAP -- no test | correctness |
| `GeminiMock` = false | line 80 | GAP -- no test | correctness |

### 3c. `IsDevelopment()` (lines 129-131)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| AppEnv == "development" -> true | 130 | GAP -- no unit test | correctness |
| AppEnv == "production" -> false | 130 | GAP -- no unit test | correctness |

### 3d. `LogValue()` (lines 135-155)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| AI fields included in output (ai_quota_enabled, gemini_timeout, gemini_mock) | 149-151 | GAP -- no test verifies AI fields appear in LogValue | nice-to-have |
| Sensitive fields masked (gemini_api_key) | 148 | GAP -- no test | security-critical |

### 3e. `masked()` (lines 158-163)

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| Non-empty string -> "***" | 161-162 | GAP -- no unit test | security-critical |
| Empty string -> "" | 159-160 | GAP -- no unit test | security-critical |

---

## 4. `internal/metrics/ai.go`

**No test file exists for `internal/metrics/`.**

### 4a. Metric Registration (lines 11-63)

All 6 metrics use `promauto` which auto-registers with the default Prometheus registry at import time. No explicit test needed for registration itself.

| Metric | Declared | Used in Production Code | Test Verifying Increment | Severity |
|--------|----------|------------------------|--------------------------|----------|
| `AIRequestsTotal` | line 11 | `ai.go:143,170,179,188,198,211,330,355` | GAP -- no test reads the metric counter | nice-to-have |
| `AIRequestDuration` | line 20 | `ai.go:212,356` | GAP -- no test reads the histogram | nice-to-have |
| `AICacheHitsTotal` | line 29 | `ai.go:107,283` | GAP -- no test reads the counter | nice-to-have |
| `AICacheMissesTotal` | line 39 | `ai.go:111,296` | GAP -- no test reads the counter | nice-to-have |
| `AIQuotaDenialsTotal` | line 48 | `ai.go:127,312` | GAP -- no test reads the counter | nice-to-have |
| `AITokensTotal` | line 57 | `ai.go:156,157,343,344` | GAP -- no test reads the counter | nice-to-have |

**Cross-reference verification:** All 6 declared metrics ARE used in production handler code (`internal/api/ai.go`). No orphan metrics exist. The label dimensions are consistent between declaration and usage.

---

## 5. `internal/api/ai.go` -- Handler-Level Gaps (supplementary, scoped to config/wire-up concerns)

These are Phase 4 handler paths directly relevant to the config and wire-up scope of this review:

| Code Path | Line(s) | Test Status | Severity |
|-----------|---------|-------------|----------|
| `srv.llm == nil` -> 503 "AI features not configured" (NL search) | 63-66 | GAP -- no test creates server without calling SetAIDeps | correctness |
| `srv.llm == nil` -> 503 "AI features not configured" (summarize) | 236-239 | GAP -- no test | correctness |
| `cfg.AIQuotaEnabled = false` -> quota check skipped entirely | 114 | GAP -- no test sets AIQuotaEnabled=false | security-critical |
| `resolveAIQuotaLimit()` -- GetAIQuotaOverride DB error (fallthrough) | 372-374 | GAP -- no test | correctness |
| `resolveAIQuotaLimit()` -- tier context missing from ctx | 377-378 | GAP -- no test | correctness |
| `retryAfterMidnight()` -- secs <= 0 clamp to 1 | 472-474 | GAP -- no unit test | nice-to-have |
| `buildSummaryInput()` -- all Optional fields nil | 411-428 | GAP -- no unit test for CVE with all-nil optional fields | correctness |
| `buildSummaryInput()` -- all Optional fields populated | 411-428 | GAP -- no unit test (integration test implicitly populates some) | correctness |
| Summarize cache unmarshal failure -> fall through to LLM | 286-288 | GAP -- no test | correctness |

---

## Summary

### What's Well-Covered

- **Store-level quota operations** are tested via `TestQuotaCmd_SetAndGet` and `TestQuotaCmd_Delete`, confirming that `SetAIQuotaOverride`, `GetAIQuotaOverride`, `ListAIQuotaOverridesForOrg`, and `DeleteAIQuotaOverride` work correctly at the data layer.

- **Feature name validation** is covered by `TestQuotaCmd_SetInvalidFeature`, which exercises the cobra command end-to-end and confirms that unrecognized feature names are rejected before any DB call.

- **AI retention cleanup** is covered by `TestRunner_AICleanup` in the retention package, which exercises the full cleanup pipeline including `AILogRetentionDays` being passed through `retentionHandler()` in main.go.

### Gap Counts by Severity

| Severity | Count |
|----------|-------|
| **security-critical** | **12** |
| **correctness** | **30** |
| **nice-to-have** | **27** |
| **Total** | **69** |

### Security-Critical Gaps (12)

1. `validateConfig()` -- no test for JWT_SECRET < 32 bytes rejection (main.go:480-481)
2. `validateConfig()` -- no test for JWT_SECRET >= 32 bytes acceptance (main.go:480)
3. `validateConfig()` -- no test for non-dev + HTTP ExternalURL rejection (main.go:483-484)
4. `validateConfig()` -- no test for non-dev + HTTPS ExternalURL acceptance (main.go:483)
5. `validateConfig()` -- no test for dev-mode HTTP bypass (main.go:483)
6. `config.Load()` -- no test for missing required fields DATABASE_URL, JWT_SECRET (config.go:122-123)
7. `AIQuotaEnabled` default=true -- no test verifies this default is applied; silent change to false disables quotas (config.go:70)
8. `LogValue()` -- no test verifies GeminiAPIKey is masked in logs (config.go:148)
9. `masked()` -- non-empty string -> "***" not tested (config.go:161-162)
10. `masked()` -- empty string -> "" not tested (config.go:159-160)
11. `cfg.AIQuotaEnabled=false` handler path -- quota check skipped entirely, untested (ai.go:114)
12. `cfg.AIQuotaEnabled=false` summarize handler path -- same skip, untested (ai.go:299)

### Key Observations

1. **CLI commands test store methods, not CLI wiring.** `TestQuotaCmd_SetAndGet` and `TestQuotaCmd_Delete` call store methods directly (e.g., `s.SetAIQuotaOverride`). They do not invoke the cobra commands. The only test that exercises a cobra command is `TestQuotaCmd_SetInvalidFeature`. The `quotaGetCmd`, `quotaListCmd`, and `quotaDeleteCmd` cobra commands have zero CLI-level tests. Notably, the "no overrides found" output paths in both `quotaGetCmd` and `quotaListCmd` are not covered.

2. **No test file for `internal/config/`.** The config package has no tests at all. Default values, required field validation, `IsDevelopment()`, `LogValue()`, and `masked()` are all untested. The `AIQuotaEnabled` default of `true` is a security-positive default -- a regression changing it to `false` would silently disable quota enforcement with no test catching it. The `masked()` function is trivial but guards against credential leakage in logs; a regression that returns the raw string would be a secret exposure.

3. **`validateConfig()` is completely untested.** This function enforces two critical security invariants (JWT secret minimum length and HTTPS requirement in production). It is called from both `runServe` and `runWorker` but has zero dedicated tests. A regression here could allow the server to start with a 1-byte JWT secret or serve over HTTP in production.

4. **`main.go` LLM branching logic is untested.** The three-way branch (`GeminiMock=true` / `GeminiAPIKey!=""` / neither) determines whether AI features are available. None of these branches has a test. The "neither" path (`llm=nil`) means AI endpoints return 503, but no test verifies this at the handler level either.

5. **No DryRun flag exists.** The special attention item about "DryRun flag" -- there is no DryRun flag in the quota commands. This is not a gap per se but worth noting as it was called out for review.

6. **Metrics are wired but observationally untested.** All 6 AI metrics declared in `internal/metrics/ai.go` are properly used in production handler code. However, no test reads metric values after handler invocations to confirm counters increment. This is acceptable as nice-to-have since the metrics are observability-only.
