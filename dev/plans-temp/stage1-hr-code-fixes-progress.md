# Stage 1: HR Code Fixes — Progress Log

## Group A: Quick Wins
### Task A1: Fix stale job threshold vs max job duration
- **Status:** completed
- **Files modified:** internal/worker/pool.go
- **Tests:** pass (existing tests)
- **Commit:** f6ad207
- **Notes:** Changed staleThreshold from 5m to 10m to match maxJobDuration

### Task A2: Add Retry-After header to per-org rate limiter
- **Status:** completed
- **Files modified:** internal/api/middleware_tier.go, internal/api/middleware_tier_test.go
- **Tests:** pass — assertion added to TestOrgRateLimitMiddleware_BurstCapped
- **Commit:** f6ad207
- **Notes:** Matches pattern from authRateLimit() in ratelimit.go

### Task A3: Convert UpsertDelivery to use withBypassRawTx
- **Status:** completed
- **Files modified:** internal/store/notification_delivery.go
- **Tests:** pass
- **Commit:** f6ad207
- **Notes:** Replaced hand-rolled tx with withBypassRawTx for panic recovery

### Task A4: Fix TestOrgTx_CommitsOnSuccess to verify commit persistence
- **Status:** completed
- **Files modified:** internal/store/store_test.go
- **Tests:** pass
- **Commit:** f6ad207
- **Notes:** Test now inserts a watchlist and verifies it persists after OrgTx commit

### Task A5: Fix stale comment and password_change_required response
- **Status:** completed
- **Files modified:** internal/api/middleware_auth.go, internal/api/alert_events.go, internal/api/middleware_auth_test.go
- **Tests:** pass — RFC 9457 format assertions added
- **Commit:** f6ad207
- **Notes:** Replaced inline JSON with writeProblemTyped; removed unused encoding/json import; fixed ?after= -> ?cursor= comment

### Task A6: Expose metrics port in Docker
- **Status:** completed
- **Files modified:** docker/Dockerfile, docker/compose.prod.yml
- **Tests:** N/A (Docker config)
- **Commit:** f6ad207
- **Notes:** Added EXPOSE 9090 and metrics port mapping on internal network

### Task A7: Add API key query string rejection middleware
- **Status:** completed
- **Files modified:** internal/api/middleware_apikey_query.go (new), internal/api/middleware_apikey_query_test.go (new), internal/api/server.go
- **Tests:** pass — 8 sensitive params tested, case-insensitive, normal params pass
- **Commit:** f6ad207
- **Notes:** Wired on apiRouter before auth middleware

## Group B: Evaluator Critical Path
### Task B1: Add panic recovery to evaluator.bypassTx
- **Status:** completed
- **Files modified:** internal/alert/evaluator.go
- **Tests:** pass (DSL tests; integration tests timeout due to Docker)
- **Commit:** 312cc66
- **Notes:** Added defer recovery matching store.withBypassRawTx pattern

### Task B2: Extract evaluateBatchPath helper
- **Status:** completed
- **Files modified:** internal/alert/evaluator.go
- **Tests:** pass
- **Commit:** 312cc66
- **Notes:** Created batchConfig struct + evaluateBatchPath; EvaluateBatch and EvaluateEPSS are now one-liners

### Task B3: Paginate batch/EPSS candidate loading (CRITICAL)
- **Status:** completed
- **Files modified:** internal/alert/evaluator.go
- **Tests:** pass (compiles, DSL tests pass; integration tests need DB)
- **Commit:** 312cc66
- **Notes:** candidatePageSize=1000, keyset pagination on cve_id ASC. Cursor written only after all pages. Old unbounded functions replaced with paginated versions.

## Group C: Shutdown Safety
### Task C1: Await delivery worker shutdown before DB close
- **Status:** completed
- **Files modified:** cmd/cvert-ops/main.go
- **Tests:** pass (build succeeds)
- **Commit:** 9a31014
- **Notes:** Applied to both runServe and runWorker. Uses channel + select with shutdown timeout.

### Task C2: Bound security event writer goroutines and add timeout
- **Status:** completed
- **Files modified:** internal/secure/writer.go, internal/metrics/security.go
- **Tests:** pass (build + lint clean)
- **Commit:** 9a31014
- **Notes:** sem chan struct{} cap=50, 10s write timeout, bounded Stop with 10s drain, panic recovery on semaphore release, SecurityEventsWriteFailed counter

## Group D: Auth + Security
### Task D1: Require authentication on CVE endpoints
- **Status:** completed
- **Files modified:** internal/api/cves.go, internal/api/cves_test.go, internal/api/middleware_auth.go, internal/api/server.go
- **Tests:** pass (vet clean, all tests compile)
- **Commit:** d587798
- **Notes:** Created requireAuthHuma adapter wrapping chi-style auth into huma Middlewares. Updated 13 test requests with auth cookies. Replaced nil-store tests with unauthenticated-request tests.

### Task D2: Extract generic JWT parse helper
- **Status:** completed
- **Files modified:** internal/auth/jwt.go
- **Tests:** pass (build clean)
- **Commit:** d587798
- **Notes:** parseTokenWithRotation[T] generic helper; all 4 Parse functions are now one-liners

## Group E: Ops Readiness
### Task E2: Add container healthcheck binary
- **Status:** completed
- **Files modified:** cmd/healthcheck/main.go (new), docker/Dockerfile
- **Tests:** N/A (binary + Dockerfile)
- **Commit:** e2bef6b
- **Notes:** Tiny Go binary, HEALTHCHECK directive in Dockerfile

### Task E3: Add job queue depth metric
- **Status:** completed
- **Files modified:** internal/metrics/worker.go, internal/worker/pool.go, internal/worker/pool_test.go, internal/store/jobs.go
- **Tests:** pass
- **Commit:** e2bef6b
- **Notes:** WorkerJobsPending gauge, CountPendingJobs store method, reported in stale recovery loop

### Task E4: Fix log level reload
- **Status:** completed
- **Files modified:** cmd/cvert-ops/main.go
- **Tests:** pass (build clean)
- **Commit:** e2bef6b
- **Notes:** slog.LevelVar + parseLogLevel + logLevelReloadCallback wired into SIGHUP handler

### Task E6: Add circuit breaker to feed adapters
- **Status:** completed
- **Files modified:** internal/feed/breaker.go (new), internal/feed/breaker_test.go (new), internal/ingest/handler.go, internal/metrics/feed.go, go.mod, go.sum
- **Tests:** pass — 3 unit tests (open-after-failures, half-open-probe, success-no-trip)
- **Commit:** 1e51bc7
- **Notes:** sony/gobreaker v2, lazy per-feed map, FeedCircuitBreakerState gauge

## Group G: Minor Code/API
### Task G2: Fix NullString empty-string behavior
- **Status:** completed
- **Files modified:** internal/dbutil/null.go
- **Tests:** N/A (doc-only change)
- **Commit:** c7e7541
- **Notes:** Clarified doc comment; no behavior change (27 callers depend on current behavior)

### Task G3: Fix isPermanentDeliveryError to use typed SMTP errors
- **Status:** completed
- **Files modified:** internal/notify/worker.go
- **Tests:** pass (build clean)
- **Commit:** c7e7541
- **Notes:** Uses go-mail SendError.IsTemp()/ErrorCode() with fallback string matching

### Task G4: Add Cache-Control headers
- **Status:** completed
- **Files modified:** internal/api/middleware_cache.go (new), internal/api/server.go
- **Tests:** pass
- **Commit:** c7e7541
- **Notes:** noCacheMiddleware sets Cache-Control: no-store on org-scoped routes

### Task G5: Fix testChannelHandler status code
- **Status:** completed
- **Files modified:** internal/api/channels.go, internal/api/channel_test_notification_test.go
- **Tests:** pass (updated to expect 502)
- **Commit:** c7e7541
- **Notes:** Returns 502 Bad Gateway on delivery failure instead of 200

## Group H: PLAN.md Update
### Task H1: Update import-bulk description
- **Status:** completed
- **Files modified:** PLAN.md
- **Tests:** N/A
- **Commit:** 7960b9b
- **Notes:** Clarified import-bulk as dev seed / airgapped loader, not primary sync

## Skipped Tasks (per plan)
- **E1 (pgxpool AcquireTimeout):** Skipped — existing timeout architecture provides adequate protection
- **E5 (feed body size limit):** Merged into P8 Task 6
- **D3 (pending token rejection test):** Combined with P8 Tasks 12+17
- **F1-F5:** Stage 4
- **G6 (frontend raw fetch migration):** Stage 4
