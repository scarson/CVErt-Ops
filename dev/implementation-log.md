# CVErt Ops — Implementation Log

> **Purpose:** Running record of what was built in each phase, implementation decisions
> that are *not* already in PLAN.md, gotchas discovered, and quality check results.
> Append a new section for each phase or significant feature block.
>
> **Not a substitute for:** commit messages (what changed), PLAN.md (the PRD/spec),
> research.md (architectural rationale), implementation-pitfalls.md (anti-patterns to avoid).

> Append new phase sections at the end of the file.

---

## Phase 0 — Repo + CI Skeleton

> **Date:** 2026-02-25
> **Commit:** `8605eef` on `dev`
> **Deliverables:** go.mod, CLI skeleton, HTTP server skeleton, first migration, CI workflow, smoke test

### Files created

| File | Purpose |
|---|---|
| `go.mod` / `go.sum` | Go 1.26 module `github.com/scarson/cvert-ops` |
| `cmd/cvert-ops/main.go` | cobra root + `serve`, `worker`, `migrate`, `import-bulk` subcommands |
| `internal/config/config.go` | `Config` struct via `caarlos0/env/v11`, covers all `.env.example` vars |
| `internal/api/server.go` | chi router, security headers, `/healthz`, `/metrics`, huma at `/api/v1` |
| `internal/api/smoke_test.go` | testcontainers-go smoke: `/healthz` (healthy), `/healthz` (degraded), `/metrics` |
| `migrations/embed.go` | `embed.FS` exposing `*.sql` files to the binary |
| `migrations/000001_create_job_queue.up.sql` | `job_queue` table + autovacuum tuning + CONCURRENTLY indexes |
| `migrations/000001_create_job_queue.down.sql` | `DROP TABLE IF EXISTS job_queue` |
| `sqlc.yaml` | UUID → `github.com/google/uuid.UUID` override |
| `.golangci.yml` | golangci-lint v2 config |
| `.github/workflows/ci.yml` | lint → test → govulncheck → build |

### Key dependency versions (go.mod)

| Package | Version |
|---|---|
| `github.com/go-chi/chi/v5` | v5.2.5 |
| `github.com/danielgtaylor/huma/v2` | v2.37.2 |
| `github.com/jackc/pgx/v5` | v5.8.0 |
| `github.com/prometheus/client_golang` | v1.23.2 |
| `github.com/spf13/cobra` | v1.10.2 |
| `github.com/caarlos0/env/v11` | v11.4.0 |
| `github.com/golang-migrate/migrate/v4` | v4.19.1 |
| `github.com/testcontainers/testcontainers-go` | v0.40.0 |
| `github.com/KimMachineGun/automemlimit` | v0.7.5 |

### Implementation decisions / discoveries

**huma adapter import path** — The chi adapter is at
`github.com/danielgtaylor/huma/v2/adapters/humachi`, not
`github.com/danielgtaylor/huma/v2/humachi`. PLAN.md references it as `humachi`
but doesn't give the full path. The adapters live in an `adapters/` subdirectory.

**`go mod tidy` ordering** — `go mod tidy` strips packages that aren't imported
by any `.go` file. Running it before writing source files leaves go.mod almost
empty. The correct order is: write Go files first, then run `go mod tidy` (or
accept a two-pass workflow: `go get` all deps, write files, tidy again).

**`time.NewTimer` instead of `time.Sleep` in retry loop** — PLAN.md §18.3 shows
`time.Sleep(time.Duration(attempt) * time.Second)` in the DB connection retry
example. We used `time.NewTimer` + a `select` on `ctx.Done()` / `timer.C`
instead. This makes the retry loop context-aware (cancellable on shutdown signal)
while still satisfying the linear-backoff requirement. Pitfall-safe per
pitfalls.md §timer-leak because the loop is bounded (max 10 iterations) and the
timer fires before the next iteration.

**`WriteTimeout` and `//nolint:exhaustruct`** — The `exhaustruct` linter
(configured to enforce completeness only for `net/http.Server`) would flag the
intentionally-omitted `WriteTimeout`. A `//nolint:exhaustruct` comment with the
PLAN.md citation was added at the struct literal so the rationale is co-located
with the suppression.

**`migrate` subcommand uses `stdlib.OpenDB` not pgxpool** — `golang-migrate`
requires a `*sql.DB` (database/sql interface), not a pgxpool. Used
`github.com/jackc/pgx/v5/stdlib.OpenDB(*connConfig)` to get a pgx-backed
`*sql.DB` without pulling in a separate driver (`lib/pq`). This keeps pgx as the
single Postgres driver project-wide.

**`BasicWaitStrategies()` for testcontainers** — The postgres testcontainers
module (v0.40.0) provides `postgres.BasicWaitStrategies()` which combines
`wait.ForLog("database system is ready to accept connections").WithOccurrence(2)`
and `wait.ForListeningPort("5432/tcp")`. This is critical for non-Linux hosts
(Windows, macOS) where Docker uses a proxy — the log wait alone is flaky without
the port wait.

### Quality check results

**pitfall-check:** 0 issues across all categories. All applicable patterns
correctly applied; feed adapter / alert / auth categories are N/A for Phase 0.

**plan-check §18:** 17/17 required items satisfied.
- ⚠️ `job_queue` retention cleanup: correctly deferred to Phase 5 (§21). Must add
  `job_queue` to the retention cleanup job with a 24-hour window for `succeeded`
  and `dead` rows.
- ⚠️ Schema version verification in `serve`/`worker`: advisory ("should"), not
  required ("must"). Phase 1 candidate — add a startup check that the DB schema
  version matches the expected version before accepting traffic.

### Open items carried forward

- [ ] Phase 1: add `SHOW max_connections` startup warning if `DB_MAX_CONNS` is
  dangerously high (§19.2 requirement — not implementable without a DB connection
  at Phase 0 startup-check time).
- [ ] Phase 5: include `job_queue` in retention cleanup job (24-hour window,
  bounded-batch DELETE per §21.3).
- [ ] Phase 1+: schema version verification in `serve`/`worker` before accepting
  traffic.

---

## Phase 1 — Commit 1: Schema Migrations + sqlc + Store Layer

> **Date:** 2026-02-25
> **Branch:** `dev`
> **Deliverables:** Migrations 000002 + 000003, sqlc query files, generated store layer, Phase 0 carry-forward items resolved

### Files created / modified

| File | Purpose |
|---|---|
| `migrations/000002_create_cve_core.up.sql` / `.down.sql` | CVE corpus tables: `cves`, `cve_search_index`, `cve_sources`, `cve_raw_payloads`, `cve_references`, `cve_affected_packages`, `cve_affected_cpes`, `epss_staging`; `pg_trgm` extension + trigram index |
| `migrations/000003_create_feed_state.up.sql` / `.down.sql` | `cwe_dictionary`, `feed_sync_state`, `feed_fetch_log`, `system_jobs_log` |
| `internal/store/queries/cves.sql` | sqlc queries for CVE CRUD, search index, EPSS staging, child table management |
| `internal/store/queries/feed.sql` | sqlc queries for feed sync state + fetch log |
| `internal/store/queries/jobs.sql` | sqlc queries for job queue (ClaimJob SKIP LOCKED, Complete, Fail, RecoverStaleJobs, Enqueue) |
| `internal/store/store.go` | `Store` struct + constructor (`*pgxpool.Pool` + `*sql.DB` via stdlib + sqlc `*Queries`) |
| `internal/store/generated/` | sqlc-generated code (do not edit) |
| `cmd/cvert-ops/main.go` | Added `SHOW max_connections` startup warning, schema version check, `runWorker` func, updated import-bulk stub to Phase 2 |
| `PLAN.md` | Added NVD attribution requirement to §3.2 |
| `dev/implementation-pitfalls.md` | N/A — read-only reference |
| `.golangci.yml` | Fixed v2 config format (`linters-settings` → `linters.settings`), added G117 gosec exclusion, disabled revive `var-naming`, excluded noctx from test files |
| `migrations/embed.go` | Added doc comment to exported `FS` var |
| `internal/api/smoke_test.go` | Added `//nolint:noctx` comments (httptest URLs don't need context) |
| `go.mod` / `go.sum` | Added: `json-canonicalization`, `squirrel`, `golang.org/x/time/rate`, `pqtype`, `lib/pq` (upgrade) |

### Implementation decisions / discoveries

**sqlc `pgx/v5` driver mode unavailable** — `sql_driver: "pgx/v5"` gives "unknown SQL driver" in sqlc v1.30.0 even though docs suggest it should work. Fell back to `database/sql` mode (default). The store layer uses `stdlib.OpenDBFromPool(pool)` to wrap the pgxpool as `*sql.DB` for sqlc CRUD, and exposes `pool *pgxpool.Pool` directly for complex transactions (merge pipeline, advisory locks, worker SKIP LOCKED). This is a clean separation: simple CRUD via sqlc + stdlib; complex transactions via pgx native.

**`lib/pq` dependency** — `lib/pq` was already an indirect dependency (upgraded v1.10.9 → v1.11.2). sqlc requires it for `text[]` array scanning in `database/sql` mode (`pq.Array`). No action needed; it's already present.

**sqlc `cves` table → `Cfe` type name** — sqlc mis-singularizes `cves` via English `ves`→`f` rule (like knives→knife), producing `type Cfe` instead of `type Cve`. This is suppressed via the `internal/store/generated/` lint exclusion rule; the generated type is `Cfe` but aliased transparently through store methods.

**`UpsertEPSSStaging` pitfall fix** — Initial implementation used a plain `VALUES ($1, $2, $3)` insert (always inserting). `/pitfall-check` caught this violates pitfall §2.5/§2.6: the `WHERE NOT EXISTS` guard must be DB-side, not application-side. Fixed to use `FROM VALUES ... WHERE NOT EXISTS (SELECT 1 FROM cves ...)` pattern per pitfall 2.6.

**`ClaimJob` ambiguous column** — sqlc reported "column reference queue is ambiguous" in the SKIP LOCKED subquery. Fixed by aliasing the inner SELECT: `FROM job_queue jq WHERE jq.queue = $1 ...`.

**golangci-lint v2 config format** — The `.golangci.yml` used `linters-settings:` (top-level, v1 syntax) which caused exhaustruct's `include` filter to be ignored, making exhaustruct fire on all structs instead of only `net/http.Server`. Fixed by moving settings under `linters.settings:` (v2 format).

**Phase 0 carry-forward items resolved:**
- `SHOW max_connections` warning added to `newPool()` — warns if `DB_MAX_CONNS > 80% postgres max_connections`
- Schema version check added — warns if `schema_migrations.version` ≠ `expectedSchemaVersion` (3)
- `runWorker` function added (stub, to be wired with pool in Commit 2)

### Quality check results

**pitfall-check:** 1 issue found and fixed (UpsertEPSSStaging WHERE NOT EXISTS guard). 0 remaining issues.
**golangci-lint:** 0 issues after config and code fixes.
**build:** `go build ./...` clean.
**sqlc generate:** Clean, no errors.

### Open items carried forward

- [ ] Commit 2: Wire worker pool into `runWorker` / `runServe`
- [ ] `cves` table type generated as `Cfe` (sqlc singularization quirk) — harmless but worth watching if sqlc version is updated

---

## Phase 1 — Commit 2: Worker Pool

> **Date:** 2026-02-25
> **Commit:** `2e7428f` on `dev`
> **Deliverables:** `internal/worker/pool.go`, `internal/worker/job.go`, `internal/store/jobs.go`, updated `internal/store/queries/jobs.sql` + regenerated `internal/store/generated/jobs.sql.go`, updated `cmd/cvert-ops/main.go`

### Files created / modified

| File | Purpose |
|---|---|
| `internal/worker/job.go` | `Handler` type definition (package doc lives here) |
| `internal/worker/pool.go` | `Pool` struct: per-queue polling goroutines, stale-lock recovery goroutine, `sync.WaitGroup` graceful shutdown |
| `internal/store/jobs.go` | Domain wrapper methods: `ClaimJob` (nil on no-rows), `CompleteJob`, `FailJob`, `RecoverStaleJobs`, `EnqueueJob` |
| `internal/store/queries/jobs.sql` | Fixed `RecoverStaleJobs` query (see below) |
| `internal/store/generated/jobs.sql.go` | Regenerated by sqlc after query fix |
| `cmd/cvert-ops/main.go` | Worker pool wired into `runServe` (goroutine) and `runWorker` (blocking); `feedIngestHandler` stub added |

### Implementation decisions / discoveries

**`$1::interval` cast fails with pgx extended protocol** — The original `RecoverStaleJobs` query used `locked_at < now() - $1::interval`. In PostgreSQL, `::interval` works when the input is a _text_ string (e.g., `'300'::interval` = 5 minutes), but pgx sends `int64` parameters as binary type `int8` in extended query protocol. `int8::interval` is an invalid cast in PostgreSQL and would return an error at runtime. Fixed by changing to `($1 * INTERVAL '1 second')` where `$1` is an integer number of seconds. This uses valid PostgreSQL arithmetic and keeps the generated parameter type as `interface{}`. The store wrapper passes `int64(staleAfter.Seconds())`.

**sqlc generates `interface{}` for arithmetic expressions** — After the query change, sqlc generated `dollar_1 interface{}` instead of `int64` for the `RecoverStaleJobs` parameter. sqlc can't infer the type when the parameter appears inside a multiplication expression with an interval literal. The generated function still works correctly at runtime; the store wrapper is typed.

**`pool.Start(ctx)` is blocking** — The pool's `Start` method uses an internal `sync.WaitGroup` and blocks until all goroutines exit after `ctx` is cancelled. In `runWorker` it's called directly (blocking the command until shutdown). In `runServe` it's started in a goroutine alongside the HTTP server; when the signal context cancels, both the HTTP server and pool goroutines drain concurrently.

**`store.Job` domain type** — Rather than exposing `generated.JobQueue` to the worker package (which would create a dependency on sqlc-generated types), `store/jobs.go` defines a minimal `Job` struct with only the fields the worker needs (`ID`, `Queue`, `Payload`, `Attempts`). This keeps `internal/worker` independent of the generated layer.

**`feedIngestHandler` stub** — Registers a no-op handler for the `"feed_ingest"` queue to demonstrate the wiring and prevent the pool from emitting "no handler registered" errors when feed jobs are manually enqueued for testing. Will be replaced with real dispatch logic in commits 4–8.

### Quality check results

**pitfall-check:** 0 issues. Key verified patterns:
- `time.NewTicker` + `defer ticker.Stop()` used in both `runQueue` and `runStaleRecovery` (no timer leak)
- No `defer` inside loop bodies
- `sync.WaitGroup` used for goroutine lifecycle management (not `errgroup`)
- Pool goroutines use process-lifetime signal context, not HTTP handler context

**golangci-lint:** 0 issues.
**build:** `go build ./...` clean.

### Open items carried forward

- [ ] Commits 4–8: Replace `feedIngestHandler` stub with real per-queue dispatch (adapters wire themselves in)
- [ ] Phase 2+: Consider making `pollInterval` and `staleThreshold` configurable via env vars for self-hosted tuning

---

## Phase 1 — Commit 3a: Advisory Lock Key + material_hash

> **Date:** 2026-02-25
> **Commit:** `3cc58e4` on `dev`
> **Deliverables:** `internal/merge/advisory.go`, `internal/merge/hash.go`

### Files created

| File | Purpose |
|---|---|
| `internal/merge/advisory.go` | `advisoryKey(domain, id)` — FNV-1a hash of `"domain:id"` → int64 for `pg_advisory_xact_lock`; exported `CVEAdvisoryKey` |
| `internal/merge/hash.go` | `MaterialFields` struct, `ComputeMaterialHash` (JCS + SHA-256), `normalizeCVSSVector` |

### Implementation decisions / discoveries

**G104 on `hash.Hash.Write`** — gosec fires because `hash.Hash.Write` returns `(int, error)`. The docs explicitly state it never returns an error. Fixed with `_, _ = h.Write(...)` (explicit discard).

**G115 on `int64(h.Sum64())`** — uint64→int64 reinterpretation. Zeroing the sign bit would halve hash distribution unnecessarily for advisory lock keys. Used `//nolint:gosec // G115: intentional full-range reinterpretation for advisory lock key`. (Per CLAUDE.md lint suppression policy: confirmed false positive, architecturally controlled, inline nolint with explanation.)

**`normalizeCVSSVector` sorts metrics alphabetically** — The plan specifies canonical CVSS spec metric order but that order is deterministic given the metric names, and all feeds that provide vectors use standard metric abbreviations. Sorting alphabetically achieves the same deduplication goal without hardcoding every version's spec order. This is simpler and robust against future CVSS versions.

### Quality check results

**pitfall-check:** 0 issues.
**golangci-lint:** 0 issues (after G104/G115 fixes).
**build:** `go build ./...` clean.

---

## Phase 1 — Commit 3b: CanonicalPatch Types + Field Resolver

> **Date:** 2026-02-25
> **Commit:** on `dev`
> **Deliverables:** `internal/feed/interface.go`, `internal/merge/resolve.go`

### Files created

| File | Purpose |
|---|---|
| `internal/feed/interface.go` | `CanonicalPatch` + sub-types (`ReferenceEntry`, `AffectedPackage`, `AffectedCPE`). `FeedAdapter` interface deferred to Commit 4. |
| `internal/merge/resolve.go` | Source name constants, priority lists, `ResolvedCVE`, `resolve()` function, URL canonicalization, score-diverges computation |

### Implementation decisions / discoveries

**`CanonicalPatch` lives in `internal/feed`** — not `internal/merge`, per PLAN.md package structure. Feed adapters (Commits 4–8) import `internal/feed` to produce `CanonicalPatch` values; the merge pipeline imports `internal/feed` to read them. No circular dependency.

**`internal/merge` imports `internal/store/generated` directly** — Go's `internal/` visibility rule allows this: both packages share the `github.com/scarson/cvert-ops/internal/` root. The pipeline needs `generated.CveSource` for the `resolve()` function parameter type. A store-level abstraction would just re-export the same type.

**`resolve()` handles unknown source names in union fields** — CWEs, references, packages, and CPEs are unioned from ALL sources. Sources not in a named priority list (e.g., a future "vendor" source) still contribute to union fields but never win scalar precedence. `otherSources()` helper enumerates them in sorted order for determinism.

**URL canonicalization** — `canonicalizeURL` normalizes scheme+host to lowercase, strips fragment, removes trailing path slash, sorts query params. This is a best-effort deduplication; it doesn't resolve redirects or normalize URL-encoded equivalents. Sufficient for deduplication across the 5 feed sources.

**`IsWithdrawn` OR logic for safety** — If the highest-precedence source doesn't set IsWithdrawn but a lower-precedence source does, the CVE is still marked withdrawn. This is intentional: a withdrawal signal from any source is a safety indicator worth honoring. Status (REJECTED/withdrawn string) still follows strict precedence.

**DatePublished: earliest across all sources** — Different sources record different "first published" dates for the same CVE. Taking the minimum is conservative (earliest known disclosure date).

### Quality check results

**pitfall-check:** 0 issues.
**golangci-lint:** 0 issues.
**build:** `go build ./...` clean.

### Open items carried forward

- [ ] Commit 3c: `internal/merge/pipeline.go` (Ingest), `internal/merge/fts.go` (JoinForFTS), `internal/store/cve.go` (domain wrapper methods)

---

## Phase 1 — Commit 3c: Merge Pipeline + FTS Helper + Store CVE Methods

> **Date:** 2026-02-25
> **Branch:** `dev`
> **Deliverables:** `internal/merge/pipeline.go`, `internal/merge/fts.go`, `internal/store/cve.go`

### Files created

| File | Purpose |
|---|---|
| `internal/merge/pipeline.go` | `Ingest()` — 10-step advisory-locked transaction: advisory lock → upsert source → raw payload → resolve → material_hash → upsert CVE → tombstone → child tables → EPSS staging → FTS |
| `internal/merge/fts.go` | `JoinForFTS([]string) string` — joins terms with spaces for Postgres `to_tsvector` input |
| `internal/store/cve.go` | Domain wrapper methods: `GetCVE` (nil,nil on not-found), `ListCVEs`, `GetCVESources` |

### Implementation decisions / discoveries

**`Ingest` naming avoids revive stutter** — The function was initially named `MergeCVESource`. `revive` flagged this as stuttering (`merge.MergeCVESource` — package name repeated). Per CLAUDE.md lint policy: fix code, don't suppress. Renamed to `Ingest` so callers use `merge.Ingest(...)` which reads naturally.

**`generated.New(tx)` binds sqlc to the transaction** — `*sql.Tx` satisfies the `generated.DBTX` interface (ExecContext/QueryContext/QueryRowContext/PrepareContext). Calling `generated.New(tx)` creates a `*Queries` that runs all sqlc queries inside the advisory-locked transaction. The advisory lock itself is acquired via a raw `tx.ExecContext` call before binding queries.

**Null-byte stripping on both normalizedJSON and rawPayload** — `bytes.ReplaceAll(data, []byte{0}, []byte{})` applied to both inputs before any DB write. Postgres TEXT/JSONB rejects `\x00` (pitfall §2.10). Applied at the entry point so individual adapters don't need to remember to strip.

**Nil CWEIDs → empty slice before `pq.Array`** — `pq.Array(nil)` sends NULL to a `text[] NOT NULL` column. An explicit nil-check coerces the slice to `[]string{}` before passing to `UpsertCVEParams.CweIds`.

**EPSS staging always deleted** — The staging row is unconditionally deleted (even on `sql.ErrNoRows`). A no-op DELETE is safe and prevents stale score accumulation from a race where EPSS ingestion runs while no CVE row exists yet (pitfall §2.7). The `errors.Is(err, sql.ErrNoRows)` check only gates the `UpdateCVEEPSS` call — not the `DeleteEPSSStaging` call.

**`store.DB()` accessor** — `pipeline.go` calls `s.DB()` to get the `*sql.DB` for `BeginTx`. This required exposing `DB()` on the `Store` struct. The `store.Store` already had `db *sql.DB` (set from `stdlib.OpenDBFromPool(pool)` in the constructor); `DB()` returns it.

### Quality check results

**pitfall-check:** 0 issues.
**golangci-lint:** 0 issues (after Ingest rename).
**build:** `go build ./...` clean.

### Open items carried forward

- [ ] Commit 4: `FeedAdapter` interface + MITRE CVE adapter + CISA KEV adapter

---

## Phase 1 — Commit 4: FeedAdapter Interface + MITRE + CISA KEV Adapters

> **Date:** 2026-02-25
> **Branch:** `dev`
> **Deliverables:** `internal/feed/interface.go` (updated), `internal/feed/util.go`, `internal/feed/mitre/adapter.go`, `internal/feed/kev/adapter.go`

### Files created / modified

| File | Purpose |
|---|---|
| `internal/feed/interface.go` | Added `Adapter` interface, `FetchResult`, `SourceMeta` types |
| `internal/feed/util.go` | Shared utilities: `ParseTime`, `ParseTimePtr`, `StripNullBytes`, `StripNullBytesJSON`, `ResolveCanonicalID` |
| `internal/feed/mitre/adapter.go` | MITRE CVE 5.0 ZIP adapter: temp-file streaming, FileHeader.Modified pre-filter, CVE 5.0 JSON parser, REJECTED tombstone, CNA/ADP CVSS fallback |
| `internal/feed/kev/adapter.go` | CISA KEV adapter: object-navigation streaming, catalogVersion short-circuit, `in_cisa_kev = true`, `cwes` polymorphic field |

### Implementation decisions / discoveries

**`FeedAdapter` → `Adapter` rename** — `revive` lint flagged `feed.FeedAdapter` as stuttering (package name repeated). Per CLAUDE.md: fix code, don't suppress. Renamed to `feed.Adapter`. PLAN.md uses `FeedAdapter` as a concept name but the Go type name follows idiomatic Go conventions. Concrete adapters in subpackages (`mitre.Adapter`, `kev.Adapter`) are unaffected.

**MITRE ZIP streaming pattern** — `archive/zip.NewReader` requires `io.ReaderAt` (seekable). HTTP response body is `io.ReadCloser` (forward-only). Fixed via `os.CreateTemp + io.Copy + f.Seek(0, io.SeekStart)`. `defer os.Remove` uses lambda to avoid G703 gosec false positive on `f.Name()`.

**MITRE `entry.Modified` vs `entry.FileHeader.Modified`** — `zip.File` embeds `zip.FileHeader`, so `Modified` is directly accessible as `entry.Modified`. staticcheck QF1008 flagged the explicit embedded field selector; fixed.

**KEV `cwes` field as `json.RawMessage`** — The `cwes` field was absent on pre-2023 KEV entries and added later. Defining it as `json.RawMessage` handles absent (nil), `null`, and `[]string` without panic or type error (per pitfall §1.7 polymorphic field rule).

**Cursor returned in NextCursor for single-page adapters** — pitfall-check caught that KEV discarded its computed cursor (`_ = nextCursorJSON`) instead of returning it, causing re-processing of the entire catalog on every run. Fixed: both KEV and MITRE return their new cursor in `FetchResult.NextCursor`. Feed handlers must NOT call Fetch again in a tight loop just because NextCursor != nil — KEV/MITRE cursors are for the next scheduled run.

**G704/G703 gosec suppressions** — gosec's taint analysis flags `client.Do(req)` as SSRF (G704) even when the URL is a hardcoded constant. Feed adapters use hardcoded upstream URLs (GitHub, CISA), not user-supplied URLs. Added inline `//nolint:gosec // G704: URL is a hardcoded constant` at each call site. Same for G703 (path traversal) on `os.Remove(f.Name())` from `os.CreateTemp`.

### Quality check results

**pitfall-check:** 1 issue found and fixed (KEV cursor discarded; not returned in FetchResult.NextCursor). 0 remaining issues.
**golangci-lint:** 0 issues.
**build:** `go build ./internal/feed/...` clean.

### Open items carried forward

- [ ] Commit 5: NVD adapter (`internal/feed/nvd/adapter.go`) — dynamic rate limiting, 120-day chunking, per-page cursor, resumable pagination
- [ ] Feed handler: implement actual dispatch logic to replace `feedIngestHandler` stub (Commits 4–8)
- [ ] Handler convention: for KEV/MITRE (single-page), don't re-enqueue on non-nil NextCursor

---

## Phase 1 — Commit 5: NVD Feed Adapter

> **Date:** 2026-02-25
> **Branch:** `dev`
> **Deliverables:** `internal/feed/nvd/adapter.go`

### Files created

| File | Purpose |
|---|---|
| `internal/feed/nvd/adapter.go` | NVD API 2.0 adapter: dynamic rate limiting, 120-day window chunking, 15-min overlap, per-page resumable cursor, streaming JSON parser, CVSS v3.1/v3.0/v4.0, CWE extraction, CPE deduplication |

### Implementation decisions / discoveries

**Dynamic rate limiting from NVD_API_KEY env var** — Rate limit determined at `New()` time by checking `os.Getenv("NVD_API_KEY")`. With key: 50 req/30s → `rate.Every(600ms)`; without: 5 req/30s → `rate.Every(6s)`.

**`"apiKey"` header casing** — NVD API 2.0 requires exactly `apiKey` (lowercase `a`). Go's `http.Header.Set` canonicalizes header names, which would change this to `Apikey`. Added `//nolint:canonicalheader` comment. NVD's server is case-sensitive on this header.

**Timestamp params via `url.Values` + `Z` suffix** — Query parameters via `req.URL.Query()` → `q.Set(...)` → `req.URL.RawQuery = q.Encode()`. Format `"2006-01-02T15:04:05.000Z"` uses the `Z` UTC suffix to avoid the `+00:00` form entirely (no `%2B` encoding needed).

**Cursor embeds window position + page offset** — `Cursor{WindowStart, WindowEnd, StartIndex}` persists both the date-range position and intra-window page offset. Partial failures mid-window resume from the exact page.

**120-day window + 15-minute overlap** — `windowMax = 120 * 24 * time.Hour`. After a window is exhausted, the next starts at `cur.WindowEnd - 15 minutes`. `computeNextCursor` returns nil when all available data is fetched.

**Response `timestamp` field for clock-skew safety** — NVD API 2.0 returns `timestamp` in the response body. Used as `effectiveNow` instead of `time.Now()` to avoid Docker container clock skew. Fallback chain: response body timestamp → HTTP `Date` header → `time.Now()`.

**`zeroValueCursor()` for full-history backfill** — Nil/empty cursor triggers full history backfill from `nvdEpoch = "2002-01-01"`.

**Streaming parse via Token()/More()** — `parseNVDResponse` navigates the top-level JSON object, processing the `"vulnerabilities"` array one record at a time. NVD pages can be >5 MB.

**NVD source preference for CVSS** — `pickPreferred(entries)` returns the `nvd@nist.gov`-sourced entry if present, else first entry.

**Attribution TODO** — Package comment includes `TODO(attribution): NVD notice required in UI per NVD ToU`. Phase 6+ frontend item per PLAN.md §3.2.

### Quality check results

**pitfall-check:** No issues found.
**golangci-lint:** 0 issues.
**build:** `go build ./internal/feed/nvd/...` clean.

### Open items carried forward

- [ ] Commit 6: OSV adapter (`internal/feed/osv/adapter.go`) — ZIP streaming, alias resolution, late-binding PK migration, withdrawn tombstoning
- [ ] Phase 6+: Add NVD attribution notice to UI per NVD ToU

---

## Phase 1 — Commit 6: OSV Feed Adapter + Late-Binding PK Migration

> **Date:** 2026-02-25
> **Branch:** `dev`
> **Deliverables:** `internal/feed/osv/adapter.go`, updated `internal/merge/pipeline.go`

### Files created / modified

| File | Purpose |
|---|---|
| `internal/feed/osv/adapter.go` | OSV GCS all.zip adapter: temp-file streaming, FileHeader.Modified pre-filter, alias resolution, withdrawn tombstone, affected package ranges, CVSS vectors |
| `internal/merge/pipeline.go` | Added `migrateCVEPK` helper + Step 1.5 late-binding PK migration check in `Ingest` |

### Implementation decisions / discoveries

**OSV all.zip bulk URL** — `https://osv-vulnerabilities.storage.googleapis.com/all.zip` — no auth required, public GCS bucket. ZIP contains `ECOSYSTEM/ADVISORY_ID.json` per advisory. All `.json` files are advisory entries; simple `strings.HasSuffix(name, ".json")` filter is sufficient.

**ZIP streaming pattern** — Same as MITRE: `os.CreateTemp + io.Copy + f.Seek(0) + zip.NewReader`. Explicit `_ = rc.Close()` per entry (no defer in loop — pitfall §1.8).

**Alias resolution in adapter** — `feed.ResolveCanonicalID(nativeID, aliases)` promotes a CVE ID from `aliases[]` to `patch.CVEID`. `patch.SourceID = nativeID` always (preserves native advisory ID). The merge pipeline handles the DB-level PK migration.

**Late-binding PK migration in pipeline** — Added Step 1.5 between the advisory lock and source upsert in `merge.Ingest`: if `patch.CVEID != patch.SourceID`, call `q.FindCVEBySourceID` to check if the native ID was the previous canonical PK. If yes, `migrateCVEPK` updates all child tables in order: delete `cve_search_index` first (FK reference), then UPDATE `cve_sources`, `cve_references`, `cve_affected_packages`, `cve_affected_cpes`, `cve_raw_payloads`, `epss_staging`, and finally `UPDATE cves SET cve_id = newID`. Step ordering matters because `cve_search_index` has `REFERENCES cves(cve_id)` without ON UPDATE CASCADE — deleting it first prevents FK violation on the cves PK update.

**Withdrawn tombstone** — pitfall-check caught that `patch.Status` was not set. Fixed: both `patch.IsWithdrawn = true` and `patch.Status = "withdrawn"` are set. TombstoneCVE (triggered by IsWithdrawn) NULLs out all CVSS/EPSS scores in the pipeline.

**CVSS from OSV** — OSV `severity[].score` is the full CVSS vector string (not a numeric base score). Stored in `CVSSv3Vector`/`CVSSv4Vector`; `CVSSv3Score`/`CVSSv4Score` left nil. NVD/MITRE provide the authoritative numeric scores and have higher precedence in the resolver.

**`osvRange.Events` as `json.RawMessage`** — The events array contains single-key objects (`{"introduced": "X"}`, `{"fixed": "X"}`, `{"last_affected": "X"}`). Per pitfall §1.7, polymorphic event objects use `json.RawMessage` and are parsed via `json.Unmarshal(ev, &map[string]string{})`.

**`details` preferred over `summary`** — OSV has both `summary` (short) and `details` (Markdown, longer). `details` is used as `description_primary`; falls back to `summary` if details is empty.

### Quality check results

**pitfall-check:** 1 issue found and fixed (withdrawn tombstone missing `patch.Status = "withdrawn"`). 0 remaining issues.
**golangci-lint:** 0 issues.
**build:** `go build ./...` clean.

### Open items carried forward

- [x] Commit 7: GHSA adapter — see below
- [ ] Late-binding PK migration race: concurrent ingest of same native-ID advisory during migration window is self-correcting on next sync (low probability event in practice)
- [x] OSV all.zip URL verified: `curl -I` confirms HTTP 200, 1.09 GB, `Last-Modified: Wed, 25 Feb 2026 21:57:24 GMT` — URL is correct and updated continuously. Note: research agents are blocked from web access in this environment; `curl` via Bash tool works fine as a substitute for URL verification.

---

## Phase 1 — Commit 7: GHSA Feed Adapter

> **Date:** 2026-02-25
> **Branch:** `dev`
> **Deliverables:** `internal/feed/ghsa/adapter.go`

### Files created

| File | Purpose |
|---|---|
| `internal/feed/ghsa/adapter.go` | GHSA REST API adapter: cursor pagination via Link header, incremental sync via `updated>=` filter, alias resolution, `withdrawn_at` tombstone, affected packages from inline `vulnerabilities[]` array |

### Implementation decisions / discoveries

**REST API chosen over GraphQL** — The GHSA research agent (with verified web access via updated `AGENT.md`) confirmed the REST `GET /advisories` endpoint is superior to GraphQL for this adapter:
- Response is a top-level JSON array (simpler streaming — no wrapper key to navigate past)
- `cve_id` is a direct top-level field (no need to parse `identifiers[]`)
- `vulnerabilities[]` is inline per-advisory (no nested pagination required in GraphQL)
- Same rate limits (5,000 req/hr authenticated)
Endpoint: `GET https://api.github.com/advisories`. Auth: `Authorization: Bearer $GITHUB_TOKEN`. Required headers: `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`.

**Pagination via Link header** — GitHub uses RFC 5988 `Link` response header with `rel="next"` for cursor pagination (not GraphQL `pageInfo.endCursor`). `parseLinkHeader` extracts the `after` param from the next-page URL. 100 records per page (`per_page=100`).

**Incremental sync** — `sort=updated&direction=asc` with `updated=>=TIMESTAMP` (GitHub search date range syntax). `url.Values.Set()` + `url.Values.Encode()` handles percent-encoding of `>=` and `:` chars. 15-minute lookback overlap applied to cursor. Sort ascending so cursor advances monotonically — prevents large re-ingestion window on mid-page failure.

**Type filter: `type=reviewed` only** — Unreviewed advisories lack structured CVE data and are out of scope for the corpus. Malware type excluded. Document this filter choice: `?type=reviewed`.

**Rate limit** — 5,000 req/hr authenticated (60/hr unauthenticated — effectively unusable for backfill). Adapter uses `rate.NewLimiter(rate.Every(1*time.Second), 1)` — well within the 1.39 req/sec ceiling. Token read from `GITHUB_TOKEN` env var.

**All pages in single Fetch call** — Full backfill is ~5,000 reviewed advisories (~50 pages at 1 req/sec = ~50 seconds). Acceptable within job timeout. Same pattern as OSV/KEV adapters.

**Alias resolution** — `cve_id` top-level field checked first (direct); `identifiers[]` where `type="CVE"` checked as fallback. `feed.ResolveCanonicalID(nativeID, aliases)` produces canonical ID. `patch.SourceID = nativeID` (always the GHSA ID).

**`withdrawn_at` tombstone** — Non-null `withdrawn_at` → `IsWithdrawn = true` + `Status = "withdrawn"`. Pipeline TombstoneCVE step NULLs out CVSS/EPSS scores.

**CVSS from `cvss_severities`** — Prefer `cvss_severities.cvss_v3`/`cvss_v4` (explicit version split) over the top-level `cvss` field (no version distinction). Top-level `cvss` used as V3 fallback.

**Affected packages from `vulnerabilities[]`** — GHSA provides `first_patched_version` as a string and `vulnerable_version_range` as a free-form string. Synthetic OSV-format events `[{"introduced":"0"},{"fixed":"VERSION"}]` constructed via `json.Marshal` (not string concatenation — avoids injection if version string contains special chars). `RangeType = "ECOSYSTEM"`.

**`feed-researcher` AGENT.md fix** — The OSV research agent (previous session) silently fell back to training data when web tools were unavailable. Updated `AGENT.md` to: (1) make WebSearch/WebFetch mandatory, (2) require success before writing anything, (3) define explicit failure message if tools unavailable rather than silent fallback.

### Quality check results

**pitfall-check:** No issues found.
**golangci-lint:** 0 issues.
**build:** `go build ./internal/feed/ghsa/...` clean.

### Open items carried forward

- [x] Commit 8: EPSS adapter — see below
- [x] OSV all.zip URL verified via `curl -I` — HTTP 200, 1.09 GB (see Commit 6 notes)

---

## Phase 1 — Commit 8: EPSS Enrichment Adapter

> **Date:** 2026-02-25
> **Branch:** `dev`
> **Deliverables:** `internal/feed/epss/adapter.go`, `internal/feed/epss/adapter_test.go`

### Files created

| File | Purpose |
|---|---|
| `internal/feed/epss/adapter.go` | EPSS enrichment adapter: gzip CSV streaming, line-1 comment parsing, two-statement IS DISTINCT FROM pattern with per-CVE advisory lock |
| `internal/feed/epss/adapter_test.go` | Unit tests for parseLine1, score_date RFC3339 format verification, null byte stripping, rate limiter non-nil |

### Implementation decisions / discoveries

**Does NOT implement `feed.Adapter`** — EPSS is an enrichment adapter, not a CVE source. It exposes `Apply(ctx, *store.Store, cursorJSON) (cursorJSON, error)` and writes directly to the DB via the two-statement pattern (PLAN.md §5.3).

**Domain change** — Canonical URL is `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`. The old domain `epss.cyentia.com` redirects HTTP 301 to this domain. Verified via `curl` on 2026-02-25.

**`score_date` is RFC3339, not a plain date** — Line 1 of the CSV is `#model_version:v2025.03.14,score_date:2026-02-25T12:55:00Z`. The `score_date` field contains a full RFC3339 timestamp (including time component), not a plain `YYYY-MM-DD` date. Training data had this wrong. Verified live. Uses `feed.ParseTime()` multi-layout parser.

**`bufio.Reader` for line 1, `encoding/csv` for the rest** — `bufio.NewReader(gz).ReadString('\n')` reads the non-CSV comment line. The same `bufio.Reader` is passed to `csv.NewReader`, which picks up from line 2 onward. First `cr.Read()` discards the CSV header line 2. `cr.ReuseRecord = true` avoids one allocation per row; CVE ID cloned via `strings.Clone` before next read.

**Two-statement pattern, advisory lock** — Per PLAN.md §5.3 and pitfall §2.8:
- Per-row transaction begins → `pg_advisory_xact_lock(merge.CVEAdvisoryKey(cveID))` (same key as merge pipeline, prevents TOCTOU race)
- Statement 1 (`UpdateCVEEPSS`): `UPDATE cves SET epss_score=... WHERE ... IS DISTINCT FROM ...` — no-op if unchanged
- Statement 2 (`UpsertEPSSStaging`): `INSERT INTO epss_staging WHERE NOT EXISTS (SELECT 1 FROM cves ...)` — only writes if CVE not yet in corpus
- Both statements run unconditionally; `RowsAffected` never inspected

**Short-circuit cursor check** — If `cursor.score_date` date (UTC) matches today's UTC date, skip the download. File is published once daily; the 24h rate limiter is a second guard.

**Model version warning** — `slog.WarnContext` when `model_version` changes between runs — all ~250k scores shift non-incrementally and analysts may want to know why alert thresholds behave differently.

**research-findings directory moved** — User moved `docs/research-findings/` to `dev/research-findings/` (end-user docs vs developer reference). Git history records the move.

### Quality check results

**pitfall-check:** No issues found.
**golangci-lint:** 0 issues.
**go test:** All tests pass (`ok github.com/scarson/cvert-ops/internal/feed/epss`).
**build:** `go build ./internal/feed/epss/...` clean.

### Open items carried forward

- [x] Commit 9: CVE search + detail API (`internal/api/cves.go`) — see below

---

## Phase 1 — Commit 9: CVE Search + Detail API

> **Date:** 2026-02-25
> **Branch:** `dev`
> **Deliverables:** `internal/api/cves.go`, updated `internal/store/cve.go`, updated `internal/api/server.go`, updated `internal/api/smoke_test.go`, updated `cmd/cvert-ops/main.go`, 3 new sqlc queries

### Files created / modified

| File | Purpose |
|---|---|
| `internal/api/cves.go` | 3 CVE endpoints: `GET /cves` (paginated search), `GET /cves/{cve_id}` (detail + child tables), `GET /cves/{cve_id}/sources` (per-source payloads) |
| `internal/store/cve.go` | Added `GetCVEDetail`, `SearchParams`, `SearchCVEs` (squirrel dynamic query) |
| `internal/store/queries/cves.sql` | Added `GetCVEReferences`, `GetCVEAffectedPackages`, `GetCVEAffectedCPEs` queries |
| `internal/api/server.go` | Changed `NewRouter(db *pgxpool.Pool)` → `NewRouter(s *store.Store)`; removed `_ = api` placeholder; wired `registerCVERoutes(api, s)` |
| `internal/api/smoke_test.go` | Updated `api.NewRouter(pool)` → `api.NewRouter(store.New(pool))` |
| `cmd/cvert-ops/main.go` | Created store once (`st := store.New(db)`), passed to both `worker.New(st)` and `api.NewRouter(st)` |

### Implementation decisions / discoveries

**`NewRouter` accepts `*store.Store` not `*pgxpool.Pool`** — The router now needs the full store to call `registerCVERoutes`. The `healthzHandler` still needs the pool for ping, so `s.Pool()` is called inside `NewRouter` (nil-safe: when `s == nil`, `db` stays nil and healthz returns degraded).

**`squirrel` for dynamic search** — `sq.StatementBuilder.PlaceholderFormat(sq.Dollar)` produces `$1, $2, …` positional params. `sq.Eq{"c.severity": []string{…}}` generates `c.severity IN ($1,$2,…)` — safe for severity (5 bounded values). FTS uses `websearch_to_tsquery` (Postgres 11+, supports quoted phrases and negation).

**COALESCE on nullable columns** — CVSS: `COALESCE(c.cvss_v4_score, c.cvss_v3_score)` — prefers v4, falls back to v3. EPSS min filter: `COALESCE(c.epss_score, -1)` (NULLs below any ≥0 threshold); EPSS max filter: `COALESCE(c.epss_score, 2)` (NULLs above any ≤1 threshold). Both prevent NULL rows vanishing from pagination results.

**Keyset cursor as row comparison** — `(c.date_modified_canonical, c.cve_id) < (?, ?)` uses Postgres row comparison semantics: `A < C OR (A = C AND B < D)`. Both columns are DESC, both appear in ORDER BY and WHERE — correct composite keyset. `date_modified_canonical` is `NOT NULL DEFAULT now()` so no COALESCE needed on the cursor column itself.

**EXISTS subquery for ecosystem/package filter** — A JOIN on `cve_affected_packages` causes duplicate rows when one CVE affects multiple packages in the same ecosystem. EXISTS subquery avoids duplicates without needing a DISTINCT (which would break cursor-based row counts).

**`pq.Array` for `text[]` scanning in squirrel rows** — sqlc-generated `Scan` handles `pq.Array` internally. For squirrel-built queries, the scan must explicitly use `pq.Array(&c.CweIds)` for the `cwe_ids text[]` column.

**`defer rows.Close()` at function scope** — Declared immediately after `QueryContext` returns, before the `for rows.Next()` loop. Fires at function return, not per-iteration. ✅

**Cursor encoding** — `base64.RawURLEncoding` (no padding, URL-safe) wraps `{"d":"<RFC3339Nano>","id":"<cve_id>"}`. Opaque to clients; decoded and validated server-side.

**`GetCVEDetail` returns nil on not-found** — Returns `(nil, nil, nil, nil, nil)` when the CVE doesn't exist. Handler converts to `huma.Error404NotFound`.

**`GetCVESourcesHandler` — 404 vs empty list** — First calls `GetCVE` to check existence. If CVE not found → 404. If found but no sources (shouldn't happen in production) → 200 `{"sources":[]}`.

### Quality check results

**pitfall-check:** No issues found. Key verifications:
- `defer rows.Close()` at function scope, not inside scan loop ✅
- `sq.Eq{"c.severity": slice}` — severity is bounded to 5 values, no 65,535 param panic risk ✅
- No `time.After` or background goroutines in handlers ✅
- Keyset cursor uses both `date_modified_canonical` (NOT NULL) and `cve_id` tiebreaker ✅
- COALESCE applied to nullable EPSS and CVSS columns in filter clauses ✅

**golangci-lint:** 0 issues.
**build:** `go build ./...` clean.

### Post-commit fix: huma pointer panic + cves_test.go

> **Commit:** `9f5beec` — discovered while running `go test ./...`

**huma v2 panics on pointer query params** — `huma.Register` panics at route
registration with `panic: pointers are not supported for form/header/path/query
parameters` if any query/path/header/form field uses a pointer type. This
triggered via `TestSmokeHealthzDegraded` → `api.NewRouter(nil)` →
`registerCVERoutes` → panic during `huma.Register` for `ListCVEsInput` (which
had `*float64`, `*bool`, `*string` query tags).

**Fix:** Changed `ListCVEsInput` to use non-pointer types in struct tags:
- `*string` optional params (`DateFrom`, `DateTo`, `CWEID`, `Ecosystem`,
  `PackageName`) → `string` (empty = no filter)
- `*bool` params (`InCISAKEV`, `ExploitAvail`) → `string` (`"true"`,
  `"false"`, or `""`)
- `*float64` params (`CVSSMin`, `CVSSMax`, `EPSSMin`, `EPSSMax`) → removed
  from struct tags entirely; kept as untagged `*float64` fields populated by
  `Resolve`

**`huma.Resolver` interface for optional numeric/bool params** — Added
`Resolve(ctx huma.Context, _ *huma.PathBuffer) []error` to `ListCVEsInput`.
It delegates to the extracted internal method `resolveOptionalFilters(queryFn
func(string) string) []error` for testability. This avoids implementing the
full `huma.Context` interface (~15 methods incl. `*tls.ConnectionState`,
`url.URL`, `*multipart.Form`) in tests.

**`huma.ErrorDetail` for validation errors** — Resolver returns
`&huma.ErrorDetail{Message, Location, Value}` for out-of-range numeric params.
These are returned as part of a 422 Unprocessable Entity response by huma.

**`nilIfEmpty` helper** — `func nilIfEmpty(s string) *string` returns nil for
empty strings; used to convert `string` query params to `*string` for
`store.SearchParams` fields.

**Unit tests added** (`internal/api/cves_test.go`, `package api` white-box):
18 tests covering cursor encode/decode, `nilIfEmpty`, `parseQueryDate` (4
subtests), and `resolveOptionalFilters` (11 subtests for all numeric/bool
params including boundary and invalid inputs).

---

## Phase 1 — Pure-Function Unit Tests

> **Date:** 2026-02-25
> **Commit:** `4419e4a` on `dev`
> **Deliverables:** `internal/merge/hash_test.go`, `internal/merge/resolve_test.go`, `internal/feed/util_test.go`, additions to `internal/api/cves_test.go`

### Context

After Commit 9, a TDD gap was identified: the core pure functions in the
`merge/` and `feed/` packages had no tests despite containing complex,
bug-prone logic (source precedence, hash normalization, alias resolution).
These functions require no DB connection and are ideal candidates for fast,
isolated unit tests.

### Files created / modified

| File | Tests | What is exercised |
|---|---|---|
| `internal/merge/hash_test.go` | 10 | `ComputeMaterialHash`: determinism, field sensitivity (severity, in_cisa_kev, CVSS vector), CWE/CPE/pkg insertion-order independence, nil slice == empty slice, `normalizeCVSSVector`: empty, reordering, prefix preservation, idempotence |
| `internal/merge/resolve_test.go` | 20 | `resolve()`: MITRE wins status/description over NVD, NVD wins CVSS v3 over GHSA, IsWithdrawn primary-source path, IsWithdrawn OR logic (any-source fallback), DatePublished picks earliest, DatePublished nil when no source provides it, CWE union sorted+deduped, CISA KEV any-source, ExploitAvailable any-source, score-diverges threshold (≥2.0 → true, <2.0 → false, no-scores → false), reference dedup by canonical URL, distinct URLs preserved, pkg priority OSV wins over GHSA on collision, DateModifiedSourceMax picks latest source timestamp, malformed JSON source skipped gracefully |
| `internal/feed/util_test.go` | 15 | `ParseTime`: RFC3339Nano, RFC3339, no-timezone, date-only, invalid→zero, empty→zero, UTC output; `ParseTimePtr`: nil on empty, nil on invalid, non-nil on valid; `StripNullBytes`: removes nulls, no-op on clean; `StripNullBytesJSON`: removes nulls from bytes; `ResolveCanonicalID`: alias found, no alias, nil aliases, first CVE alias wins, native-is-CVE passthrough |
| `internal/api/cves_test.go` | +4 | `cfeToItem`: all-nil sql fields → nil pointers, nil CWEIDs → empty slice (not JSON null), all optional fields set correctly, timestamps formatted as RFC3339 (not Nano) |

**Total new tests in this commit:** 49 (+ the 18 from `9f5beec` = 67 test
functions across the `api`, `merge`, and `feed` packages, up from 2 in Phase 0).

### Implementation decisions / discoveries

**`package merge` for white-box resolve tests** — `resolve()` and
`computeScoreDiverges()` are unexported. Tests use `package merge` (same
package) to access them directly. This is the standard Go pattern for white-box
unit testing of unexported functions.

**`makeSource` helper in resolve_test.go** — Marshals a `feed.CanonicalPatch`
into `generated.CveSource.NormalizedJson`. The merge pipeline reads sources from
the DB as JSON and unmarshals them — this helper faithfully recreates that
path in tests without needing a real DB.

**`makeSourceWithDate` variant** — Adds `sql.NullTime` to `SourceDateModified`
for the `DateModifiedSourceMax` test. Otherwise that field always remains nil in
test data.

**`affectedPkgKey` is unexported** — `hash_test.go` uses `package merge` to
access the `affectedPkgKey` struct directly for the package-order test.

**Canonical URL dedup uses trailing-slash stripping** — `TestResolveRefDeduplicatedByCanonicalURL` uses `"https://example.com/advisory"` vs `"https://example.com/advisory/"` (trailing slash). `canonicalizeURL` strips trailing slashes via `strings.TrimRight(u.Path, "/")`, so both map to the same canonical form.

**`cfeToItem` tested for nil→empty CWEIDs** — The `NOT NULL DEFAULT '{}'`
database column can still return `nil` in Go when `pg.Array` produces an empty
Go slice from a `text[] = '{}'` value. `cfeToItem` guards this with `if
item.CWEIDs == nil { item.CWEIDs = []string{} }` to prevent `null` in JSON
responses. Test verifies this contract.

### Quality check results

**go test `./internal/merge/... ./internal/feed/... ./internal/api/...`:** All
tests pass. No failures.
**go test `./...` -short:** All packages pass (0 failures, 0 skips relevant to
new tests).
**golangci-lint:** 0 issues.

---

## Phase 2b — Watchlists, Alert DSL, Evaluator, HTTP Handlers

> **Dates:** 2026-02-27 – 2026-02-28
> **Branch:** `dev`
> **Commits:** `c24160d` (migrations), `1a8e606` (store), `e63cb84` (DSL), `2544226` (evaluator), `40fd8b5` (handlers), `552a68d` (refinements)
> **Deliverables:** Migrations 000013-000016, store layer, DSL compiler, alert evaluator, HTTP handler layer for watchlists + alert rules + alert events

### Files created / modified

| File | Purpose |
|---|---|
| `migrations/000013_create_watchlists.{up,down}.sql` | `watchlists` + `watchlist_items` tables, RLS, indexes |
| `migrations/000014_create_alert_rules.{up,down}.sql` | `alert_rules` table, RLS, check constraint on status |
| `migrations/000015_create_alert_rule_runs.{up,down}.sql` | `alert_rule_runs` table for run telemetry |
| `migrations/000016_create_alert_events.{up,down}.sql` | `alert_events` table, `UNIQUE(org_id, rule_id, cve_id, material_hash)` |
| `internal/store/watchlist.go` | Watchlist + item CRUD with `withOrgTx` |
| `internal/store/alert_rule.go` | Alert rule CRUD, run tracking, event insert/resolve/list |
| `internal/store/queries/alert_rules.sql` | sqlc queries for all alert rule operations |
| `internal/alert/dsl/` | DSL types, parser, validator, compiler (49 tests) |
| `internal/alert/evaluator.go` | `Evaluator`: realtime/batch/EPSS paths, activation scan, zombie sweep, dry-run |
| `internal/alert/rule_cache.go` | Thread-safe in-memory cache of compiled rules |
| `internal/api/watchlists.go` | CRUD + item management HTTP handlers |
| `internal/api/alert_rules.go` | Create/get/list/patch/delete/validate/dry-run handlers |
| `internal/api/alert_events.go` | List handler with `?rule_id=` + `?cve_id=` filters |
| `internal/api/server.go` | All Phase 2b routes registered + `SetAlertDeps` |
| `cmd/cvert-ops/main.go` | Wire alert cache + evaluator into server, bump `expectedSchemaVersion` to 16 |

### Key implementation decisions

**Three evaluation paths (PLAN.md §10.5):**
- **Realtime** (`EvaluateRule`): fires on CVE upsert when `material_hash` changes. Called with a candidate set already narrowed to the changed CVE.
- **Batch** (`EvaluateBatch`): periodic job over `date_modified_canonical > last_cursor`. Skips rules with `is_epss_only = true`. Uses `candidateCap = 5000` guard.
- **EPSS** (`EvaluateEPSS`): daily job over `date_epss_updated > last_cursor`. Only runs rules with `has_epss_condition = true`.
- All paths: filter `cves.status NOT IN ('rejected', 'withdrawn')`.

**Activation flow:** Handler creates rule with `status='activating'` → returns 202. Worker (`EvaluateActivation`) does the full backfill scan, then transitions to `'active'`. The HTTP path never runs a scan inline.

**`alert_events` dedup:** `INSERT ... ON CONFLICT (org_id, rule_id, cve_id, material_hash) DO NOTHING RETURNING id`. If `id` is nil in Go (`sql.ErrNoRows`), the event already existed — no fan-out. This is the "exactly-once" guarantee.

**`bypassTx` vs `readTx` vs `withOrgTx`:**
- `withOrgTx`: org-scoped transactions for all API handler paths; sets `app.org_id`.
- `bypassTx`: worker-only; sets `app.bypass_rls='on'`. **MUST NOT be called from HTTP handlers.**
- `readTx` (new): `BeginTx(ReadOnly: true)` + always `ROLLBACK`. Used for dry-run evaluation from API paths — safe, no side effects, no RLS bypass.

**Atomic PATCH status transition:** `UpdateAlertRule` SQL includes `status = $10` so content update and status→`'activating'` happen in one transaction. Previously it was two calls (`UpdateAlertRule` + `SetAlertRuleStatus`), creating a window for inconsistency.

**Open-mode auto-org:** Only the first registered user gets an auto-org (`priorCount == 0`). Subsequent users need to create their own org via `POST /api/v1/orgs` or be invited. Cross-org isolation tests must account for this: "Bob's empty list" tests can't use Bob's orgID if Bob hasn't created an org.

**UpdateAlertRuleParams.Status:** Adding `Status string` to the store wrapper + SQL required running `sqlc generate` and fixing the existing `TestUpdateAlertRule` store test (which was passing the Go zero value `""` — now rejected by the DB check constraint).

**sqlc note — `UpdateAlertRuleParams` conflict:** The store wrapper and the generated package both define `UpdateAlertRuleParams`. The wrapper type is in `internal/store` and the generated type is in `internal/store/generated`. The wrapper passes through to the generated type internally. This is the standard pattern used throughout this codebase.

### Quality check results

**pitfall-check:** Found 1 issue (DryRun used `bypassTx` — RLS bypass from API handler is a security violation). Fixed by adding `readTx` helper.
**plan-check (§9, §10, §16):** Found missing dry-run HTTP endpoint (PLAN.md §10.6). Fixed by adding `dryRunHandler`.
**security-review:** Found non-atomic PATCH status transition. Fixed by including `Status` in `UpdateAlertRuleParams`.
**go test `./...`:** All tests pass.
**golangci-lint:** 0 issues.

### Test coverage

| Test file | New tests | Coverage |
|---|---|---|
| `internal/alert/dsl/*_test.go` | 49 | Parse, validate, compile, all operators, EPSS detection |
| `internal/alert/evaluator_test.go` | Multiple | Activation scan, zombie sweep, batch eval |
| `internal/api/watchlists_test.go` | Multiple | CRUD, item management, RBAC |
| `internal/api/alert_rules_test.go` | Multiple | CRUD, draft, validate, invalid DSL (create + patch), cross-org isolation, viewer RBAC |
| `internal/api/alert_events_test.go` | Multiple | List, rule_id filter, cve_id filter, cross-org isolation |

### Open items for Phase 3

- [x] Notification delivery (PLAN.md §11): webhook channels, email, Slack; delivery worker — Phase 3a/3b
- [x] `POST /api/v1/orgs/{org_id}/notification-channels` CRUD — Phase 3a
- [x] Fan-out: `sync.WaitGroup` per-channel, independent error recording (no `errgroup`) — Phase 3a
- [x] Outbound webhook: `doyensec/safeurl` client, redirect disabled, 10s timeout
- [x] Scheduled reports / digests (PLAN.md §12) — Phase 3b

---

## Code Review — Phases 2a & 2b

> **Date:** 2026-02-28
> **Commits:** `d758717` (Phase 2a fixes), `4643b59` (Phase 2b fixes)

Post-implementation code reviews found several issues across both phases.

### Phase 2a fixes (`d758717`)

- **Rate limiting:** Wired per-IP token bucket rate limiter into register, login, and refresh handlers with enforcement tests
- **RBAC:** Added caller-role cap to `createInvitationHandler` (defense-in-depth)
- **Invitation email match:** Added email match check in `acceptInvitationHandler`
- **Rate limiter cleanup:** Added shutdown mechanism (`done` channel + `Stop` method) to `ipRateLimiter`
- **Bootstrap atomicity:** Replaced racy `CountUsers` + `CreateOrgWithOwner` with atomic `BootstrapFirstUserOrg` using `pg_advisory_xact_lock`
- **OAuth parity:** Added `BootstrapFirstUserOrg` to GitHub and Google OAuth new-user paths; added `Name` claim to `googleClaims`
- **Cleanup:** Removed `NewRouter` shim, updated smoke tests to use `NewServer` directly
- Added 6 process guardrails to `dev/implementation-pitfalls.md` §8

### Phase 2b fixes (`4643b59`)

- **RLS bypass:** Added `withOrgRawTx` helper for squirrel queries needing `SET LOCAL app.org_id`; fixed `ListWatchlists`, `ListWatchlistItems`, `ListAlertRules`, `ListAlertEvents` — all now use `withOrgRawTx` instead of bare pool queries; added RLS isolation tests using `AppStore` (NOBYPASSRLS)
- **ILIKE escaping:** Escape `%`, `_`, `\` wildcards in text and `affected.package` DSL patterns
- **PATCH state machine:** Block DSL changes while activating (409), track status transitions (`draft→activating`, `active→disabled`, `error→activating`); cache eviction on DSL change, disable, and delete
- **API contract:** Create accepts `enabled:bool` (not status string), always returns 201; validate response includes warnings, `is_epss_only`, `has_epss_condition`; alert events include `material_hash`
- **Alert events:** Added `last_match_state` and `since` query filters; added keyset pagination (`first_fired_at DESC, id DESC`)

---

## Phase 3a — Notification Delivery (Webhooks)

> **Dates:** 2026-02-28
> **Branch:** `dev`
> **Commits:** `d14b411` (migrations), `77dc455`–`7b02fa7` (store), `6fd4e7c`–`283499a` (notify), `7ae85ad`–`0fa477d` (api), `5ff808b` (wiring), `83d0cf1` (quality fixes), `1c9712e`–`7d572ac` (test coverage)
> **Deliverables:** Migration 000017, notification channels CRUD, delivery dispatcher, webhook sender with HMAC, delivery worker with retry/backoff, API handlers

### Files created / modified

| File | Purpose |
|---|---|
| `migrations/000017_create_notification_tables.{up,down}.sql` | `notification_channels` (soft-delete, webhook), `alert_rule_channels` (M:M join, `org_id` denormalized), `notification_deliveries` (queue, autovacuum tuning) |
| `internal/notify/webhook.go` | `Send()` with HMAC-SHA256 signing, safeurl client, response body drain via `io.LimitReader`, denied-header filter, dual-signature for secret rotation |
| `internal/notify/dispatcher.go` | `Fanout()`: list channels → build CVE snapshot → `UpsertDelivery` per channel with debounce |
| `internal/notify/worker.go` | Five tickers (claim/stuck/recovery/digest/aiCleanup), per-org semaphore, exponential backoff with jitter |
| `internal/notify/client.go` | `BuildSafeClient()` with `MaxConnsPerHost: 50`, redirect disabled, 10s timeout |
| `internal/api/channels.go` | Channel CRUD + `validateWebhookURL` SSRF static check + `clearSecondarySecretHandler` |
| `internal/api/bindings.go` | Rule-channel `PUT/DELETE/GET` binding endpoints |
| `internal/api/deliveries.go` | List/detail/replay delivery endpoints |
| `internal/store/notification_channel.go` | Channel CRUD with `RotateSigningSecret`, `ClearSecondarySecret` |
| `internal/store/notification_delivery.go` | Claim/mark/retry/exhaust/recovery queries |
| `internal/alert/evaluator.go` | Injected `Dispatcher`, calls `Fanout` after `alert_event` commit |

### Key implementation decisions

**Two-transaction gap is intentional.** Alert events written in `bypassTx`; after commit, `Fanout()` runs in fresh `withOrgTx`. Orphaned-event recovery scan (5-min ticker) closes the gap.

**Debounce via partial unique index.** `UNIQUE (rule_id, channel_id) WHERE status = 'pending'` — multiple CVE events from same rule accumulate into one pending delivery's payload JSONB array. Deviates from PLAN.md's per-event idempotency key but provides equivalent dedup with correct debounce semantics.

**Two-step claim.** `ClaimPendingDeliveries` (`SELECT FOR UPDATE SKIP LOCKED`) + `MarkDeliveriesProcessing` (`UPDATE → processing`). Crash between steps is safe: rows stay in `pending`, never entered `processing`.

**Per-org semaphore as blocking channel send.** Intentional backpressure — bounded by delivery timeout and stuck-reset recovery.

**Secondary-secret dual-signing.** Diverges from design doc ("sender never emits secondary") — actual implementation emits `X-CVErtOps-Signature-Secondary` during rotation grace period for simpler receiver logic.

### Quality check results

**pitfall-check:** Clean.
**plan-check (§11, §16):** Found missing `MaxConnsPerHost`, secondary signing support, `validateWebhookURL` static check. All fixed in `83d0cf1`.
**security-review:** Found delivery cursor RFC3339 format mismatch (encode vs parse). Fixed.
**go test `./...`:** All tests pass.
**golangci-lint:** 0 issues.

---

## Phase 3b — Email Channels, Templates, Scheduled Digests

> **Dates:** 2026-02-28 – 2026-03-01
> **Branch:** `dev`
> **Commits:** `79a4b1c`–`1742e5f` (migrations), `200d227`–`567bbc7` (store), `d3e0628`–`6dcb71f` (notify), `8219f16`–`e377437` (api), `47ee37b` (wiring), `978a1eb` (quality fixes), `770f3c2` (test coverage), `b36723c` (pitfalls)
> **Deliverables:** Migrations 000018–000019, email delivery, HTML/text templates, digest runner, scheduled report CRUD, report-channel bindings

### Files created / modified

| File | Purpose |
|---|---|
| `migrations/000018_create_scheduled_reports.{up,down}.sql` | `scheduled_reports` (soft-delete, RLS) + `report_channels` join table |
| `migrations/000019_phase3b_channel_delivery_alterations.{up,down}.sql` | `notification_channels`: nullable `signing_secret`, `'email'` type. `notification_deliveries`: `kind` discriminator, nullable `rule_id`, `report_id` FK, compound check constraint |
| `internal/notify/email.go` | `EmailSend()` via `go-mail` dial-per-send, BCC all recipients, header injection defense |
| `internal/notify/template.go` | `CVESummary`, `AlertTemplateData`, `DigestTemplateData` structs; `snapshotsToCVESummaries()` with 280-char truncation |
| `internal/notify/render.go` | `RenderAlert()`, `RenderDigest()` — templates from `embed.FS`, per-file parse (no `{{define}}` collision), `funcMap` with `deref`/`pct`/`sevColor` |
| `internal/notify/digest.go` | `runDigest()`, `executeDigestReport()`, `ComputeNextRunAt()`, DST-safe `advanceNextRunAt` via `AddDate(0,0,1)` |
| `templates/email_{alert,digest}.{html,txt}.tmpl` | Four HTML/text template files for alert and digest emails |
| `internal/api/reports.go` | Scheduled digest report CRUD + channel bindings |
| `internal/api/channels.go` | Email channel validation, signing secret guards |
| `internal/store/scheduled_report.go` | Report CRUD, `ClaimDueReports`, `DigestCVEs`, `AdvanceReport` |
| `internal/store/report_channel.go` | Report-channel bindings, unified channel deletion guard |

### Key implementation decisions

**Delivery-time rendering.** Payload stored as structured JSON; templates applied at delivery time. Template updates apply to pending deliveries.

**`AddDate(0,0,1)` for DST correctness.** `Add(24*time.Hour)` drifts ±1h across DST boundaries.

**Missed-run catch-up.** Single delivery covering the full gap; skip ahead to next future slot. No flood of one-per-missed-interval.

**SMTP 5xx is permanent.** `isPermanentSMTPError` string-matches codes 550–555 (go-mail doesn't expose typed SMTP codes). Permanent failures exhaust immediately; 4xx uses existing exponential backoff.

**`deliver_kind_fk_check` compound CHECK.** Enforces `(kind='alert' AND rule_id NOT NULL AND report_id IS NULL) OR (kind='digest' AND rule_id IS NULL AND report_id IS NOT NULL)` — belt-and-suspenders against app-layer bugs.

**Template namespace isolation.** Each template file parsed into its own `*template.Template` instance — `{{define "body"}}` in alert doesn't shadow `{{define "body"}}` in digest.

**Digest truncation at 25 CVEs.** Cap summaries at 25 with `Truncated` flag and `TotalCount` for "N of M shown" footer.

### Gotchas discovered

- **Subject sanitization applied in two places** — `sanitizeSubject()` in `render.go` and `strings.NewReplacer` in `EmailSend()`. Render is primary defense; EmailSend is belt-and-suspenders.
- **Existing `nc_webhook_url` CHECK is already email-safe** — `type != 'webhook' OR jsonb_exists(config, 'url')` evaluates TRUE for email rows without modification.
- **Migration ordering is load-bearing** — 000018 must run before 000019 (`report_id` FK depends on `scheduled_reports` table).
- **Debounce index recreation** — new kind-aware indexes created CONCURRENTLY before dropping old ones (no unprotected window).

### Deferred items

- Watchlist-scoped digest filtering (schema column present, implementation deferred)
- AI executive summary in digests (`ai_summary` field plumbed, no LLM call yet)
- Weekly/custom recurrence (daily hardcoded; trivial to extend)
- Email bounce processing
- Custom user-provided templates (Enterprise feature)

### Quality check results

**pitfall-check:** Clean after fixes.
**plan-check (§11, §12, §16):** Found missing SSRF check in PATCH, `send_on_empty` default, digest truncation. All fixed in `978a1eb`.
**security-review:** Clean.
**Test coverage audit:** Found 20+ gaps, all addressed in `770f3c2` — store (DigestCVEs, InsertDigestDelivery, etc.), pure functions (isPermanentSMTPError 11-case, advanceNextRunAt), API (PATCH SSRF 5 cases, PATCH email 3 cases, DELETE 409 report-bound), worker integration (email digest delivery).
**go test `./...`:** All tests pass.
**golangci-lint:** 0 issues.

---

## Phase 4 — AI Gateway, NL Search, Summarization & Saved Searches

> **Dates:** 2026-03-01
> **Branch:** `dev`
> **Commits:** `8464e6d`–`89dfa49` (migrations), `d7eaed4` (config), `3c4a8ad` (DSL extension), `619da89`–`c8b0215` (ai package + metrics), `681881c`–`64bbc8b` (store), `b30caf1`–`148be86` (ai + DSL executor), `014eda7` (CLI), `3130316`–`044c71e` (api handlers), `5e0d526` (wiring), `b7a8459` (audit fixes), `2c5885d`–`914540c` (test coverage), `9ac07e7` (code review remediation)
> **Deliverables:** Migrations 000020–000024, `internal/ai` package, NL search & summarize handlers, saved search CRUD, Gemini adapter, quota/cache/logging system, Prometheus metrics, `quota` CLI command

### Files created / modified

| File | Purpose |
|---|---|
| `migrations/000020_create_ai_quota_tables.{up,down}.sql` | `ai_usage_counters`, `ai_quota_overrides` |
| `migrations/000021_create_ai_cache.{up,down}.sql` | `ai_cache` with unique index on `(org_id, feature, prompt_version, input_hash)` |
| `migrations/000022_create_ai_request_log.{up,down}.sql` | `ai_request_log` (audit log, `user_id` NOT a FK — survives user deletion) |
| `migrations/000023_create_saved_searches.{up,down}.sql` | `saved_searches` (soft-delete, `user_id ON DELETE SET NULL`) |
| `migrations/000024_saved_searches_constraints.{up,down}.sql` | Partial unique index on name, CHECK on nl_query length |
| `internal/ai/ai.go` | `LLMClient` interface, `GenerateResult`, `SummarizeResult`, `CVESummaryInput` types |
| `internal/ai/gemini.go` | `GeminiClient` — structured output for NL search, zero-tool-access for summarize, temp 0/0.2 |
| `internal/ai/schema.go` | `BuildSchemaDescription()` + `PromptVersion()` with `sync.Once` caching, SHA-256 prompt versioning |
| `internal/ai/mock.go` | `MockClient` with `Err` field for failure injection |
| `internal/ai/sanitize.go` | `Sanitize()` — strip markdown links, HTML tags, control chars |
| `internal/ai/quota.go` | `TierLimits`, `ResolveLimit()` (override > tier > free fallback) |
| `internal/metrics/ai.go` | 6 Prometheus counters/histograms for AI requests, cache, quotas, tokens |
| `internal/store/ai.go` | 13 store methods for quota, cache, and request log operations |
| `internal/store/saved_search.go` | Saved search CRUD with visibility filtering |
| `internal/store/dsl_executor.go` | `ExecuteDSLQuery` — shared between NL search, saved search execute, and future uses; handles FTS JOINs, keyset pagination, `limit+1` trick |
| `internal/alert/dsl/field.go` | `fts_query` field with `matches` operator for full-text search; `ExportFieldDescriptions()` |
| `internal/api/ai.go` | `nlSearchHandler`, `summarizeHandler`, `parseIntParam`, `isValidCVEID`, `truncateForLog` |
| `internal/api/saved_searches.go` | Full CRUD + execute endpoint, RBAC via `canModifySavedSearch()` |
| `cmd/cvert-ops/main.go` | LLM client init, `SetAIDeps` wiring, AI cleanup tickers, `expectedSchemaVersion = 24` |
| `cmd/cvert-ops/quota.go` | `quota` CLI subcommand for managing per-org overrides |

### Key implementation decisions

**`GenerateResult`/`SummarizeResult` wrap response + token counts.** Enriched beyond design doc to avoid a second call to get token counts from the same response object.

**`sync.Once` for schema description.** `BuildSchemaDescription()` and `PromptVersion()` computed once per process. Deterministic output (fields sorted by name) ensures stable SHA-256 `prompt_version` for cache key stability.

**DSL compiler extended with `Joins []string`.** `CompiledRule` gained a `Joins` field. `ExecuteDSLQuery` iterates `compiled.Joins` and calls squirrel `.Join()` for each. The `fts_query` field generates `JOIN cve_search_index si ON c.cve_id = si.cve_id`. FTS available universally wherever DSL is compiled.

**`ExecuteDSLQuery` queries `s.db` directly (no org transaction).** The `cves` table is global, unscoped, no RLS. Shared `cveColumns` and `scanCVERow` prevent column-order drift with `SearchCVEs`.

**Quota: increment-before-call, decrement-on-infra-failure.** Count increments atomically before LLM call. On Gemini network/500 errors, `DecrementAIUsage` called and 503 returned. Over-quota races accepted as negligible.

**Cache is non-critical-path.** `GetAICache` and `PutAICache` failures logged but do not abort the request.

**Per-org cache keys.** Prevents cross-org leakage if org-specific context added to prompts later.

**Summarize cache key = `cve_id + material_hash`.** Auto-invalidates when CVE content materially changes.

**Summarize uses `FunctionCallingConfigModeNone`.** Prevents prompt injection via attacker-controlled CVE descriptions from enabling Gemini tool use.

**Temperature 0 for NL search, 0.2 for summarize.** Deterministic for cache hit rates vs. natural language variance.

**Tier resolution hardcoded to "free".** No `tier` column on `orgs` yet. Wired but dormant until Phase 5.

**RBAC for saved searches is application-layer.** RLS enforces org isolation; private-vs-shared enforced in handler via `canModifySavedSearch()`.

### Gotchas discovered

- **Table name is `ai_request_log` (singular)** — used `ai_request_logs` in test SQL queries, causing `relation does not exist` errors.
- **`toNullInt32(0)` maps zero to NULL** — intentional to distinguish "not measured" from "measured zero" in request log.
- **`hasBlockingErrors` needed, not `len(valErrs) > 0`** — DSL validator distinguishes warnings from blocking errors.
- **`genai.Schema{}` (empty) for polymorphic `value` field** — specifying a type would break number/boolean condition values.
- **`ai_request_log.user_id` is NOT a FK** — log survives user deletion as audit record.
- **`dsl_executor.go` column list must stay in sync with `cve.go`** — main fragility point of shared `scanCVERow`.
- **`CleanupOrphanedPrivateSavedSearches` uses `bypassTx`** — must operate across all orgs for a given user.
- **MockClient `OutputTokens` values** — `GenerateStructured` returns 20, `Summarize` returns 25. Test expectations must match.

### Test coverage

| Test file | New tests | Coverage |
|---|---|---|
| `internal/api/ai_test.go` | 17 | NL search success/empty/long/quota/cache/LLM-failure/unauth/1000-char boundary, summarize success/not-found/invalid-id/quota/cache/LLM-failure/unauth, token persistence, parseIntParam (9 subtests) |
| `internal/api/saved_searches_test.go` | 12+ | CRUD, execute, RBAC (viewer create, shared modify, private access), cross-org isolation, name/nl_query length validation, patch validation |
| `internal/notify/worker_test.go` | 1 | AI cleanup retention gate |

### Quality check results

**plan-audit (§13, §14, §19.5):** Found missing RBAC alignment, Gemini tool access, validation gaps. All fixed in `b7a8459`.
**security-review:** Found CVE ID format bypass (no validation), log truncation missing. Fixed.
**pitfall-check:** Found `ai_cache` upsert missing `IS DISTINCT FROM`. Fixed.
**Test coverage audit (2 rounds):** Round 1 found 8 gaps (CVE ID validation, saved search limits, retention gate, token persistence, invalid CVE format). Round 2 found 6 more (LLM failure paths, unauth access, 1000-char boundary, parseIntParam). All addressed in commits `2c5885d` and `914540c`.
**go test `./...`:** All tests pass.
**golangci-lint:** 0 issues.

### Code review remediation (`9ac07e7`)

Full code review of Phase 4 (`163c6a0..914540c`) identified 2 Important and 3 Minor issues. All addressed:

| ID | Severity | Finding | Fix |
|---|---|---|---|
| I-1 | Important | `saved_searches_name_uq` scoped to `(org_id, name)` — contradicts design doc's per-user uniqueness | Changed to `(org_id, user_id, name)` in migration 000024 |
| I-2 | Important | `ListSavedSearches` returns unbounded result set | Added `LIMIT @result_limit::int` to sqlc query, handler validates 1–200 (default 200) |
| M-1 | Minor | `SearchCVEs` uses `c.*` while `ExecuteDSLQuery` uses `cveColumns` — column drift risk | Changed `SearchCVEs` to use shared `cveColumns` slice |
| M-2 | Minor | Quota consumed on cache hits (cache hits are free — no LLM API cost) | Moved cache check before quota in both NL search and summarize handlers |
| M-3 | Minor→Important | `NewGeminiClient` makes network call at startup — blocks startup if Gemini unreachable | Rewrote to lazy initialization with `sync.Mutex`; `getClient(ctx)` creates underlying client on first use, retries automatically on failure |

**M-2 testing implication:** Quota exhaustion tests now use unique inputs per request (unique query strings for NL search, unique CVE IDs for summarize) to prevent cache hits from silently not consuming quota.

**M-3 design principle:** No external networking dependencies in the critical startup path. Self-hosters may not use AI features or may block outbound Gemini traffic. Application startup must depend only on local resources (config, database, filesystem).

### Open items for Phase 5

- [x] Tier enforcement (org tiers, tier-gated quotas — currently hardcoded to "free") — completed in Phase 5A
- [x] Data retention automation (ai_request_log, ai_usage_counters integrated with §21 policies) — completed in Phase 5B
- [ ] AI summary execution in digests (field plumbed, no LLM call yet)
- [ ] Burst/rate limiting on AI endpoints (per-minute, complementing daily quotas)
- [ ] CVE enumeration defense (predictable sequential IDs in summarize path)

---

## Phase 5A — Tier System & Per-Org Rate Limiting

> **Date:** 2026-03-01
> **Commits:** `b11d356`..`9caba0b` on `dev`
> **Plan:** `dev/plans/2026-03-01-phase5-implementation-plan.md`

### What was built

| Feature | Files | Description |
|---|---|---|
| Tier migration | `migrations/000025_org_tier.{up,down}.sql` | Added `tier TEXT NOT NULL DEFAULT 'free'` with CHECK constraint and `tier_overrides JSONB` to `organizations` table |
| Tier resolver | `internal/tier/resolver.go` | Resolves effective limits with override precedence: per-org override > tier default > free fallback. `IntLimit()` and `BoolFlag()` methods |
| Store: org tier queries | `internal/store/org.go`, `internal/store/queries/org.sql` | `GetOrgTier`, resource count queries for alert rules, watchlists, members (+ pending invitations) via sqlc |
| Tier resolution middleware | `internal/api/middleware_tier.go` | Loads org tier from DB (or cache), injects `*tier.Resolver` into request context |
| Per-org rate limiter | `internal/api/org_ratelimit.go` | Token-bucket rate limiter keyed by org UUID. Background goroutine evicts idle entries. Tier-aware rates: free=60, pro=300, enterprise=1000 req/min |
| Resource count gating | `internal/api/alert_rules.go`, `internal/api/watchlists.go`, `internal/api/orgs.go` | Tier-gated limits on alert rules, watchlists, and org members (including pending invitations) |
| Channel type gating | `internal/api/channels.go` | Free tier restricted to webhook channel type only |
| GET org tier endpoint | `internal/api/org_tier.go` | Returns resolved tier limits for the authenticated org |
| AI quota wiring | `internal/api/ai.go` | Wired AI summary quota resolution to real org tier instead of hardcoded defaults |
| Tier cache | `internal/api/tier_cache.go` | 30s TTL in-memory cache for org tier data. `maps.Clone` for copy safety on overrides. Background eviction loop |

### Key implementation decisions

- **Override precedence: per-org JSONB > tier defaults > free** — enables sales-driven customization without schema changes
- **30s tier cache TTL** — avoids per-request DB query while keeping tier changes responsive. `maps.Clone` for copy safety since override values are scalars
- **Fail-closed tier gating** — if `tier.Resolver` is missing from context (middleware ordering bug), handlers return 500 rather than silently allowing the request
- **Pending invitations count toward member limits** — prevents circumventing limits by sending many invitations before acceptance

### Tests added

| Test | File | What it verifies |
|---|---|---|
| Tier resolver unit tests | `internal/tier/resolver_test.go` | Override precedence, tier fallback, free default |
| Org tier store integration | `internal/store/org_tier_test.go` | GetOrgTier, resource count queries against real Postgres |
| Tier middleware unit tests | `internal/api/middleware_tier_test.go` | Context injection, DB error handling, cache hit/miss |
| Org rate limiter unit tests | `internal/api/org_ratelimit_test.go` | Allow/deny, burst, idle eviction, rate change handling |
| Tier gating integration | `internal/api/tier_gating_test.go` | Resource limits, channel type gating, rate limiting, fail-closed behavior |
| Tier cache unit tests | `internal/api/tier_cache_test.go` | TTL expiration, idle eviction, copy safety (mutation isolation) |

### Quality checks

- All tests pass (`go test ./...`)
- Code review remediation applied (copy safety test for tier cache, doc comments)

---

## Phase 5B — Retention Cleanup with Bounded-Batch Deletes

> **Date:** 2026-03-01
> **Commits:** `80808c6`..`234df6b` on `dev`
> **Plan:** `dev/plans/2026-03-01-phase5-implementation-plan.md`

### What was built

| Feature | Files | Description |
|---|---|---|
| Retention indexes migration | `migrations/000026_retention_indexes.{up,down}.sql` | `CREATE INDEX CONCURRENTLY` on `cve_raw_payloads(ingested_at)`, `feed_fetch_log(started_at)`, `job_queue(finished_at) WHERE status IN ('succeeded','dead')` |
| Retention config | `internal/config/config.go` | Env vars for per-table retention windows: `RETENTION_RAW_PAYLOAD_DAYS`, `RETENTION_FEED_FETCH_LOG_DAYS`, `RETENTION_JOB_QUEUE_HOURS`, etc. |
| Retention sqlc queries | `internal/store/queries/retention.sql`, `internal/store/retention.go` | 9 bounded-batch DELETE queries using `WITH doomed AS (SELECT ... LIMIT batch_size) DELETE ... USING doomed` pattern |
| Retention runner | `internal/retention/runner.go` | Bounded-batch delete loop per table with max runtime deadline. Two phases: global tables (no org filtering), then tier-gated tables (grouped by per-org retention window) |
| Worker scheduling | `cmd/cvert-ops/main.go`, `internal/notify/worker.go` | Retention job registered as `retention_cleanup` handler, scheduled via `notify.Worker` ticker |

### Key implementation decisions

- **Bounded-batch delete pattern** — `WITH doomed AS (SELECT ... ORDER BY ts LIMIT batch_size) DELETE ... USING doomed`. Prevents long-running transactions and lock contention
- **Max runtime deadline** — Runner checks wall-clock time between batches, stops if deadline exceeded
- **Tier-gated retention windows** — Org-scoped tables group orgs by effective retention window via `tier.Resolver`. Orgs with unlimited retention (`days < 0`) are skipped
- **Error isolation** — Per-table errors are logged but don't stop the run

### Tests added

| Test | File | What it verifies |
|---|---|---|
| Retention store integration | `internal/store/retention_test.go` | All 9 bounded-batch deletes against real Postgres — batch limits, cutoff filtering |
| Runner unit tests | `internal/retention/runner_test.go` | Batch looping, max runtime, disabled skip, context cancellation, tier-gated grouping |
| Error isolation test | `internal/retention/runner_test.go` | Failing table doesn't prevent subsequent tables from being cleaned |

### Quality checks

- All tests pass (`go test ./...`)
- Code review remediation: removed dead AI cleanup code, added error isolation test, relocated `HasPendingOrRunningJob`

---

## Phase 5C — Audit Logging, SSO Connections, OIDC Login Flow

> **Date:** 2026-03-01 to 2026-03-02
> **Commits:** `03ca3a3`..`0feb8f2` on `dev`
> **Plan:** `dev/plans/2026-03-01-phase5-implementation-plan.md`

### What was built

| Feature | Files | Description |
|---|---|---|
| Audit log migration | `migrations/000027_audit_log.{up,down}.sql` | `audit_log` table with RLS, autovacuum tuning. No FK to `organizations` or `users` — audit records survive entity deletion |
| Secret redaction | `internal/audit/redact.go` | Write-time redaction using keyword-based substring matching (secret, password, api_key, token, etc.) |
| Audit writer | `internal/audit/writer.go` | Non-blocking inserts via goroutines with `context.WithoutCancel`. `sync.WaitGroup` for deterministic test flushing |
| Audit integration in handlers | All mutation handlers | All create/update/delete handlers emit audit entries with old_state/new_state snapshots |
| Audit log list endpoint | `internal/api/audit_log.go` | `GET /api/v1/orgs/{org_id}/audit-log` with admin+ RBAC, enterprise tier gating, keyset pagination |
| AES-256-GCM crypto | `internal/crypto/aes.go` | Encrypt/Decrypt for OIDC client secrets at rest |
| SSO connections migration | `migrations/000028_sso_connections.{up,down}.sql` | `sso_connections` (one per org, `client_secret_enc BYTEA`) and `sso_email_domains`. Both with RLS |
| SSO CRUD handlers | `internal/api/sso.go` | Create/Get/Patch/Delete SSO connection + PUT domains + domain discovery. Enterprise tier gated, owner-only RBAC |
| OIDC login flow | `internal/api/oauth_oidc.go` | SSO login initiation + callback with ID token verification. Does NOT auto-create users — requires pre-existing linked identity |
| Mock OIDC IdP | `internal/testutil/mock_oidc.go` | Test utility serving OIDC discovery, JWKS, and token endpoints with real RSA-signed ID tokens |

### Key implementation decisions

- **Non-blocking audit writes** — `context.WithoutCancel` detaches from request lifecycle. Errors logged, never propagated to API callers
- **Write-time redaction (not read-time)** — Secrets stripped before INSERT, ensuring they never reach the database
- **Audit log intentionally FK-free** — `org_id` and `actor_id` are NOT foreign keys. Audit records must survive org/user deletion for compliance
- **SSO: one connection per org** — UNIQUE constraint on `sso_connections.org_id`. Simple for initial implementation
- **Client secrets encrypted at rest** — AES-256-GCM with nonce-prepended format. Masked as `"[encrypted]"` in API responses
- **OIDC login does NOT auto-create users** — Unlike Google/GitHub OAuth, SSO login requires a pre-existing linked identity. Prevents unauthorized access through misconfigured IdP
- **State parameter encodes connection_id** — `{random_hex}_{connection_uuid}` allows single callback endpoint to identify which SSO connection to use
- **OIDC provider caching** — `sync.Map` caches `*oidc.Provider` instances by issuer URL

### Tests added

| Test | File | What it verifies |
|---|---|---|
| Redaction unit tests | `internal/audit/redact_test.go` | Keyword matching, URL redaction, nested map recursion |
| Writer unit tests | `internal/audit/writer_test.go` | Non-blocking insert, Flush determinism, email resolution fallback |
| Audit store integration | `internal/store/audit_test.go` | Insert/List with pagination, filters, RLS enforcement |
| Audit handler tests | `internal/api/audit_log_test.go` | RBAC, enterprise tier gating, pagination, filters |
| Audit integration tests | `internal/api/audit_integration_test.go` | All mutation handlers emit correct audit entries |
| AES-256-GCM unit tests | `internal/crypto/aes_test.go` | Encrypt/decrypt round-trip, wrong key rejection, nonce uniqueness |
| SSO store integration | `internal/store/sso_test.go` | CRUD, email domain management, RLS, encryption round-trip |
| SSO handler tests | `internal/api/sso_test.go` | CRUD, domain management, tier gating, RBAC, discovery |
| OIDC login/callback tests | `internal/api/oauth_oidc_test.go` | Full OIDC flow with mock IdP — login, callback, token exchange, nonce validation, conflict detection |

### Quality checks

- All tests pass (`go test ./...`)
- Code review remediation: email resolution in audit writer, invitation audit logging, file renames

---

## Phase 5D — SSO Identity Linking + Audit Logging

> **Date:** 2026-03-02
> **Commits:** `75bca91` (identity linking), `4909767` (audit logging) on `dev`
> **Plan:** `dev/plans/2026-03-01-phase5-implementation-plan.md`, Tasks 25–27

### What was built

| Feature | Files | Description |
|---|---|---|
| SSO identity linking | `oauth_oidc.go`, `server.go` | Two-endpoint OIDC flow: `GET /orgs/{org_id}/sso/link` (org-scoped, auth required) + `GET /auth/oidc/link-callback` (public, reads user from JWT cookie) |
| Conflict detection | `oauth_oidc.go` | Link callback checks `GetUserByProviderID` before upserting — returns 409 if identity already linked to different user; idempotent for same-user re-link |
| OIDC helper extraction | `oauth_oidc.go` | `oidcBuildOAuthConfig`, `oidcInitRedirect`, `oidcVerifyCallback` — shared by login and link flows, ~100 lines deduplication |
| SSO audit logging | `sso.go`, `oauth_oidc.go` | Audit entries for SSO connection create/update/delete and identity linking |

### Key implementation decisions

- **Link callback is a public route** — no RequireAuthenticated middleware. The user's JWT is read from the `access_token` cookie manually (same pattern as `ParseAccessToken`). This is because the OIDC callback URL must be pre-registered with the IdP and can't have auth middleware blocking the redirect.
- **Delete handler reads before deleting** — `deleteSSOHandler` now loads the connection before calling `DeleteSSOConnection` so it can include entity details (ID, display_name) in the audit trail.
- **Link callback loads connection for orgID** — `oidcLinkCallbackHandler` calls `GetSSOConnectionByID(connID)` to resolve the orgID for the audit entry, since the link callback route has no org context. Acceptable extra query on a non-hot path.
- **ActorID set explicitly in link callback** — since the route has no auth middleware, `ctxUserID` isn't in context. The audit entry sets `ActorID: &userID` directly.
- **Audit for create SSO includes client_secret** — the `NewState` map includes the plaintext `client_secret` value. The `redactSecrets` function in the audit writer automatically redacts fields matching "secret" keywords before DB write.

### Tests added

| Test | File | What it verifies |
|---|---|---|
| `TestIdentityLinking_Success` | `oauth_oidc_test.go` | Full OIDC link flow: init → redirect → callback → verify identity created in DB |
| `TestIdentityLinking_AlreadyLinked` | `oauth_oidc_test.go` | Pre-existing identity for different user → 409 Conflict |
| `TestAudit_SSOOperations` | `sso_test.go` | Create/Update/Delete sub-tests verify audit entries |
| `TestAudit_IdentityLinking` | `oauth_oidc_test.go` | Verify audit entry for identity linking with correct orgID and entity type |

### Quality checks

- **go test ./...:** All pass (transient testcontainer failures on `audit` and `retention` packages pass when run individually — Docker resource contention)
- **golangci-lint:** 0 issues

---

## Phase 5 — Cross-Phase Test Coverage Remediation

> **Date:** 2026-03-03
> **Commits:** `b636323`..`a473b05` on `dev`

### What was built

Systematic test coverage review across all phases (1-5), driven by per-phase coverage gap reports. 92 new test functions and 21 subtests added across 23 test files (2,669 insertions).

| Phase | Tests Added | Areas Covered |
|---|---|---|
| Phase 5 | ~30 | Identity linking security, SSO input validation, tier gating (enterprise unlimited), audit log input validation, retention unlimited-skip, OIDC login edge cases |
| Phase 4 | ~69 | RLS isolation for `ai_*` and `saved_search` tables (12 gaps), RBAC for saved search access control, handler error paths, DSL executor cursor tampering and limit clamping, FTS + `escapeLike`, Gemini security config white-box tests, `validateConfig` + `IsDevelopment` + `LogValue` masking |
| Phase 2 | ~210 | DSL compiler/evaluator, alert event/rule API handlers, watchlist API, RBAC middleware, CSRF middleware, auth handlers, rate limiting, store-layer RLS for all org-scoped tables |
| Phase 1 | ~60 | Pure function unit tests for all 5 feed adapter parsers, merge pipeline helpers, FTS document builder, advisory lock, worker pool; Fetch-level integration tests for all adapters |
| Cross-phase | — | Code review findings: rate limiter burst cap, SSO domain validation (RFC 1035), client_secret audit redaction, OIDC provider cache eviction, tier limit constants extracted |

### Bugs found during coverage review

| Bug | Commit | Severity | Description |
|---|---|---|---|
| Sanitizer regex bypass | `cf3e20b` | Security | `![alt](url)` markdown images passed through the LLM sanitizer. Also added stripping of Unicode format characters (bidi overrides, zero-width spaces, BOM) |
| SearchCVEs FTS JOIN broken | `05b3a4c` | Correctness | `SearchCVEs` used `FROM "cves c"` alias but `cveColumns` references unaliased `"cves.col"`. When FTS JOIN was present, Postgres rejected the query. Never integration-tested, shipped silently |
| Test flakiness | `3749f1b` | Test quality | Quota and rate limiter tests had timing-sensitive assertions; fixed with tolerance adjustments |

### Quality checks

- **golangci-lint:** 0 issues
- Coverage review reports: `dev/test-coverage-reports/2026-03-03-phase{1,2,3a,3b,4,5}-*-review.md` (10 reports)

---

## Frontend — Vue 3 SPA

> **Date:** 2026-03-04 through 2026-03-06
> **Commits:** `dd99764`..`9b6d40e` on `dev` (102 commits)
> **Plan:** `dev/plans/2026-03-03-frontend-design.md` (design), `dev/plans/2026-03-03-frontend-implementation-plan.md` (implementation)
> **A11y spec:** `dev/specs/accessibility-spec.md`

### What was built

| Feature | Key files | Description |
|---|---|---|
| Project scaffolding | `web/` (184 source files) | Vue 3 + TypeScript, Vite, Tailwind CSS v4, shadcn-vue (reka-ui primitives), Pinia, Vue Router 4 |
| SPA embedding in Go binary | `web/embed.go`, `internal/api/server.go` | `//go:embed all:dist` with `fs.Sub`; SPA fallback serves `index.html` for client-side routes |
| OpenAPI-typed API client | `web/src/lib/api/client.ts`, `web/src/lib/api/orgFetch.ts` | `openapi-typescript` generates types from spec; `openapi-fetch` with CSRF middleware and 401 refresh interceptor with coalesced refresh |
| Auth store | `web/src/stores/auth.ts` | Pinia store: login/logout, session restore, org context with localStorage persistence |
| Router + guards | `web/src/router/index.ts` | Auth guard, org guard, title guard with h1 focus for screen readers |
| Layouts | `web/src/layouts/` | PublicLayout (login/register) + AuthenticatedLayout (sidebar nav, org switcher, mobile sheet) |
| All views | `web/src/views/` | Login, Register, Create Org, CVE Search, CVE Detail, Watchlist List/Detail, Members, Groups, Feed Status, Invitation acceptance, Password reset, Email verification, 404 |
| Shared components | `ErrorAlert.vue`, `LoadingSkeleton.vue`, `EmptyState.vue` | Reusable error display (with retry prop), skeleton loading, empty state |
| Keyset pagination | `web/src/composables/usePagination.ts` | Cursor stack for prev/next navigation; reset on filter change |
| WCAG 2.1 AA a11y | All views/components | 10 dedicated a11y commits: `lang` attribute, skip-to-main, icon labels, `aria-live` regions, form error association, h1 focus on navigation |
| Frontend CI | `.github/workflows/ci.yml` | `test-web` (type-check + lint + vitest), `build-web` jobs; frontend build required by all Go test jobs for `embed.go` |
| Backend OAuth redirect | `internal/auth/`, `internal/config/` | `FRONTEND_URL` config; OAuth callbacks redirect to frontend instead of returning JSON |

### Key implementation decisions

- **SPA embedded in Go binary** — `//go:embed all:dist` with SPA fallback handler. Single binary deployment, no separate web server
- **Coalesced token refresh** — When multiple API calls get 401 simultaneously, a single `refreshPromise` is shared. Prevents thundering-herd refresh calls
- **Stale response guards** — All async fetches use an incrementing `fetchId` counter; responses discarded if a newer fetch was initiated
- **Two Pinia stores only** — `auth` (session/org context) and `ui` (sidebar state). YAGNI applied strictly
- **shadcn-vue for accessible primitives** — Dialog, Select, DropdownMenu come with correct ARIA roles. A11y work focused on what primitives don't cover
- **URL sanitization** — `safeHref` utility strips non-http(s) URLs from CVE references to prevent XSS via `javascript:` URLs

### Tests added

32 test files across views, components, stores, composables, and API client covering login/register flows, CVE search/detail, watchlist management, member/group management, invitation acceptance, pagination, auth store, router guards, and API client CSRF/refresh behavior.

### Gotchas discovered

- **Go nil slice → JSON `null`** — Router guard crashed on `auth.user?.orgs?.length` when orgs was `null`
- **Stale responses on rapid navigation** — Required incrementing counter pattern in every async view
- **Org switch requires explicit re-fetch** — `onMounted` doesn't re-run; all org-scoped views need `watch` on `activeOrgId`
- **Mobile sidebar Sheet stays open on navigation** — Required explicit close in router `afterEach` hook

### Quality checks

- **Type safety:** `vue-tsc --build` in CI
- **Linting:** ESLint + Prettier enforced in CI
- **Two rounds of bug hunts** identified and fixed ~20 bugs (stale responses, org-switch gaps, infinite reload loops, dialog stale state, double-submit vulnerabilities)

---

## Vendor Feed Adapters — MSRC + Red Hat

> **Date:** 2026-03-05 to 2026-03-06
> **Commits:** `d42674e`..`9499ef2` on `feature/vendor-feed-adapters`, merged to `dev`

### What was built

| Feature | Files | Description |
|---|---|---|
| CSAF 2.0 parser | `internal/feed/csaf/parser.go` | Shared OASIS CSAF 2.0 JSON parser — extracts CVE IDs, CVSS vectors/scores, CWEs, remediation URLs. Designed for reuse by MSRC now and CISA ICS-CERT later |
| MSRC adapter | `internal/feed/msrc/adapter.go` | Fetches CSAF 2.0 advisories from `api.msrc.microsoft.com`. Two-phase: queries `/updates` for modified advisory IDs, then fetches each CSAF document. Rate limited (2 req/s) |
| Red Hat adapter | `internal/feed/redhat/adapter.go` | Two-phase from Red Hat Security Data API: paginated CVE list, then individual detail requests. Rate limited (5 req/s) |
| Vendor enrichment schema | `migrations/000029_vendor_enrichment.{up,down}.sql` | `cve_vendor_enrichment` table with `(cve_id, source_name)` unique constraint, vendor severity/fix state, JSONB enrichment blob |
| Merge pipeline vendor step | `internal/merge/pipeline.go` | Vendor enrichment upsert when `CanonicalPatch.VendorEnrichment` is non-nil |
| KEV vendor enrichment | `internal/feed/kev/adapter.go` | Backfilled `VendorEnrichment` population for KEV adapter |

### Key implementation decisions

- **Shared CSAF parser** — CSAF 2.0 is an OASIS standard used by multiple vendors. Reusable `csaf` package avoids future duplication
- **Two-phase fetch pattern** — list modified IDs first, then fetch details. Enables per-CVE cursor granularity and crash recovery
- **`VendorEnrichment` as separate table** — vendor data is heterogeneous across sources. JSONB blob with extracted scalar columns for common filter dimensions
- **`slices.Concat` for priority list** — bug hunt found `append(globalPriority, ...)` was mutating the global slice's backing array
- **OData datetime validation** via regex in MSRC adapter — prevents injection into `$filter` query parameter

### Bug hunt findings (all fixed)

- Red Hat adapter never advanced cursor on last page (full re-sync every run)
- KEV enrichment fields not null-byte stripped
- MSRC silently dropped CVSS 0.0 scores
- Red Hat/MSRC response bodies not drained (broke connection reuse)
- Global priority slice mutation via `append` in merge resolver

### Tests added

| Test file | Coverage |
|---|---|
| `internal/feed/csaf/parser_test.go` | Multi-vulnerability documents, missing fields, empty input |
| `internal/feed/msrc/adapter_test.go` | Pagination, CVSS 0.0 preservation, rate limiting, cursor persistence |
| `internal/feed/redhat/adapter_test.go` | Pagination, cursor advancement, detail fetch errors, null-byte stripping |
| `internal/merge/resolve_test.go` (additions) | MSRC/Red Hat priority ordering, mutation protection |

---

## Feed Wiring — Scheduler, Admin API, Ingest Pipeline

> **Date:** 2026-03-06 to 2026-03-07
> **Commits:** `9499ef2`..`d540e85` on `dev` (PR #8)

### What was built

| Feature | Files | Description |
|---|---|---|
| Feed ingest handler | `internal/ingest/handler.go` | Generic worker handler: deserializes feed name, creates adapter via factory, paginated fetch loop with merge, cursor persistence per page for crash recovery. Exponential backoff |
| EPSS ingest handler | `internal/ingest/epss.go` | Separate handler for EPSS (uses `Apply()` not `Fetch()`). Same sync state/fetch log tracking |
| Adapter factory | `internal/ingest/feeds.go` | `NewAdapter` factory mapping feed names to concrete adapters. `KnownFeeds` canonical list |
| Feed scheduler | `internal/ingest/scheduler.go` | Periodic goroutine checking timing + backoff, enqueues jobs. Prometheus counters for enqueued/skipped |
| Admin feeds API | `internal/api/feeds.go` | `GET /api/v1/admin/feeds` (status + logs), `POST /api/v1/admin/feeds/{feed}/trigger` (manual re-run) |
| Site admin middleware | `internal/api/middleware_site_admin.go` | `RequireSiteAdmin()` — checks `is_site_admin` column. Gates admin endpoints |
| Site admin migration | `migrations/000030_add_site_admin.{up,down}.sql` | `is_site_admin BOOLEAN DEFAULT false` with `CREATE INDEX CONCURRENTLY` |
| Feed state store | `internal/store/feed.go` | Sync state CRUD + fetch log insertion. `withBypassTx` (no RLS for global feed state) |
| Shared feed utilities | `internal/feed/util.go` | Extracted `DownloadToTemp` (5GB limit), `CloneStrings`, `StripNullBytes`, `DrainBody`, `DoRequest`, `ReadResponseBody` |
| Feed status dashboard | `web/src/views/FeedStatusView.vue` | Live dashboard showing all feeds with sync state and recent fetch logs. Replaced placeholder |
| EPSS poison row handling | `internal/feed/epss/adapter.go` | Skips unparseable rows with warning log instead of aborting entire feed |
| GHSA pagination refactor | `internal/feed/ghsa/adapter.go` | Returns one page per `Fetch()` for crash recovery compatibility |

### Key implementation decisions

- **Per-page cursor persistence** — cursor state persisted after every successful page. Process crash resumes from last completed page, not the beginning. Drove the GHSA refactor
- **Job dedup via `ON CONFLICT DO NOTHING`** — eliminates TOCTOU race between scheduler and admin trigger
- **Site admin as boolean column** — YAGNI for now. Admin feed endpoints are the only consumer
- **Admin dashboard shows all known feeds** — newly registered feeds appear immediately even before first run
- **`backoffDuration` guards negative failures** — `max(failures, 0)` prevents panic from `1 << negative`

### Bug hunt findings (all fixed)

- `expectedSchemaVersion` stale (startup always warned)
- `InsertFeedFetchLog` discarded actual timestamps (used `now()` default)
- Sync state errors silently swallowed
- NVD adapter cursor regression (data race)
- EPSS blocked on malformed CSV rows
- `DownloadToTemp` had no size limit (OOM risk)
- GHSA fetched all pages internally, defeating crash recovery
- `backoffDuration` panicked on negative failure count

### Tests added

| Test file | Coverage |
|---|---|
| `internal/ingest/handler_test.go` | Success path, merge errors, cursor persistence, backoff panic guard |
| `internal/ingest/scheduler_test.go` | Interval scheduling, backoff skip, Prometheus counters, dedup |
| `internal/ingest/epss_test.go` | Success/error paths, sync state error propagation |
| `internal/api/feeds_test.go` | GET status, POST trigger, site admin gate, dedup |
| `internal/api/middleware_site_admin_test.go` | Admin/non-admin/missing-user/DB-error scenarios |
| `internal/store/feed_test.go` | Upsert idempotency, timestamp persistence |
| `internal/feed/util_test.go` | `DownloadToTemp` (5GB limit), `DoRequest`, `ReadResponseBody` |

### Quality checks

- 3 rounds of code review + 3 bug hunt campaigns
- CI pipeline updated: frontend test/build jobs, golangci-lint v2 config migration, version pinning
- Lint clean (16 feed util issues resolved)

---

## Phase 6A — Security Hardening

> **Date:** 2026-03-08 to 2026-03-09
> **Commits:** `c9cbc62`..`67f348a` on `feature/phase6a-security-hardening` (22 commits, 60 files, +4902/-236)
> **Plan:** `dev/plans/2026-03-01-phase6-implementation-plan.md`

### What was built

| Feature | Files | Description |
|---|---|---|
| Password reset flow | `internal/api/auth_password_reset.go`, `internal/store/password_reset.go`, templates, `migrations/000031_*` | Forgot/reset endpoints. 32-byte `crypto/rand` tokens, SHA-256 hashed in DB. Rate limited (3/user/hour). Always returns 200 to prevent email enumeration. Increments `token_version` to invalidate sessions |
| First-user bootstrap fix | `internal/api/auth.go` | In invite-only mode, allow first user to register without invitation |
| Invitation email sending | `internal/api/orgs.go`, `internal/notify/render.go`, templates | Sends invitation emails via SMTP on `POST /invitations`. Best-effort |
| Invitation resend endpoint | `internal/api/orgs.go` | `POST /orgs/{org_id}/invitations/{id}/resend` — new token, extended expiry. Admin+ |
| Email verification flow | `internal/api/auth_email_verification.go`, `internal/store/email_verification.go`, templates, `migrations/000032_*`, `000033_*` | Verify + resend endpoints. `email_verified` boolean on users. Same token pattern as password reset. 24h TTL |
| Channel test endpoint | `internal/api/channels.go` | `POST /orgs/{org_id}/channels/{id}/test` — sends test notification. Delivery outcome in response body |
| Account lockout | `internal/api/lockout.go` | In-memory `lockoutManager` with configurable threshold/duration. Injectable clock. Background eviction goroutine |
| RBAC for channels | `internal/api/server.go` | Channel mutations elevated from `RoleMember` to `RoleAdmin` per PLAN.md §7.3 |
| CORS middleware | `internal/api/cors.go` | Config-driven origin allowlist. Rejects wildcard `*` (incompatible with credentials). Dev defaults |
| Frontend views | `ForgotPasswordView.vue`, `ResetPasswordView.vue`, `VerifyEmailView.vue` | Vue pages + auth store extensions + routes |

### Key implementation decisions

- **Tokens SHA-256 hashed** before DB storage. Lookup by hash via index scan
- **Email enumeration prevention** — `POST /auth/forgot-password` returns constant 200 regardless of outcome
- **Lockout is in-memory** — acceptable for single-binary deployment; would need Redis for multi-instance
- **Invitation resend generates new token** rather than re-sending original (which may have leaked)
- **Channel test always returns 200** — delivery outcome in JSON body, not HTTP status

### Tests added

| Test | File | What it verifies |
|---|---|---|
| Password reset store/handlers | `password_reset_test.go`, `auth_password_reset_test.go` | Create, lookup, rate limiting, enumeration-safe response, session invalidation |
| Email verification store/handlers | `email_verification_test.go`, `auth_email_verification_test.go` | Create, lookup, expired token, resend auth |
| Account lockout | `lockout_test.go`, `auth_lockout_test.go` | Threshold, unlock timing, eviction, concurrent access, integration with login |
| CORS middleware | `middleware_cors_test.go` | Allowed/blocked origins, dev defaults, wildcard rejection |
| Channel test/RBAC | `channel_test_notification_test.go`, `channels_test.go` | Test notification, RBAC enforcement |
| Invitation resend | `orgs_test.go` | Resend for pending, rejected for expired/accepted/cancelled |
| Frontend views | `ForgotPasswordView.test.ts`, `ResetPasswordView.test.ts`, `VerifyEmailView.test.ts` | Form flows |

### Quality checks

- `golangci-lint run` passes
- Code review remediation: `formatTTL` helper, `forgotPasswordResponse` constant, test file renames
- RBAC corrected to match PLAN.md §7.3

---

## Phase 6B — Bug Hunting + Phase 6C — Plan Reconciliation

> **Date:** 2026-03-08
> **Commits:** `0926eff`..`020dc66` on `dev`

### What was done

Ran 6 bug hunt passes (3 for Phase 6A security code, 3 for Phase 6B missing-feature code) using exploratory, holistic, and multipass bug hunter skills. Identified 25 bugs across TOCTOU races, anti-enumeration leaks, memory growth, validation gaps, and transaction helper misuse. Consolidated findings into a 13-task bug fix implementation plan.

Separately, reconciled PLAN.md with the implemented API.

### Bug hunting

6 reports in `dev/bug-hunts/`:
- `2026-03-08-phase6a-holistic.md` — lockout case bypass, argon2 semaphore leak, unbounded lockout map growth, password reset TOCTOU
- `2026-03-08-phase6a-security-holistic.md` — anti-enumeration leaks in forgot-password error paths
- `2026-03-08-phase6a-security-multipass.md` — 5-pass deep analysis: contract violations, pattern breaks, state machine gaps, resource lifecycle, config edge cases
- `2026-03-08-phase6b-exploratory.md` — bootstrap registration race, concurrent invitation accept 500s
- `2026-03-08-phase6b-holistic.md` — soft-deleted orgs in `ListAllOrgs`, missing transaction wrappers
- `2026-03-08-phase6b-multipass.md` — PATCH channel empty name validation, invitation duplicate detection, CORS wildcard+credentials

Bug fix plan: `dev/plans/2026-03-08-phase6-bug-fixes.md` — 13 tasks covering all 25 findings

Testing pitfalls: `dev/testing-pitfalls.md` — 8-category checklist distilled from why tests missed these bugs

### PLAN.md reconciliation

- Appendix B rewritten from skeletal skeleton to comprehensive API reference — 60+ endpoints organized by category with role requirements
- Fixed `status` enum: added `withdrawn` (missing from §4.3 but present in implementation)
- Removed corrupt SQL fragment from §18.1
- Updated phase tracker (§18) to reflect Phases 5, Frontend, and 6 as implemented
- Fixed stale cross-references

### Other changes

- `go-chi/cors` promoted from indirect to direct dependency
- Bug hunter skills updated to output to `dev/bug-hunts/` directory

---

## Phase 6 Bug Fix Pass (2026-03-09)

25 findings from 6 bug hunt reports (3 exploratory, 2 holistic, 1 multipass), consolidated into a 13-task implementation plan. Executed via subagent-driven-development (5 batches).

### What was fixed

| Category | Fixes |
|---|---|
| TOCTOU / concurrency | Atomic password reset token consumption (`FOR UPDATE SKIP LOCKED`), bootstrap registration mutex, idempotent invitation accept (`ON CONFLICT DO NOTHING`), `COALESCE(accepted_at, now())` |
| Anti-enumeration | All `forgotPasswordHandler` post-lookup error paths return 200 (DB error, rate limit, token creation failure) |
| Memory / resource leaks | Lockout manager eviction goroutine with `Stop()` lifecycle, `t.Cleanup(m.Stop)` in all tests |
| Argon2 semaphore safety | `func(){defer release...}()` closures in `loginHandler`, `changePasswordHandler`, `resetPasswordHandler` |
| Validation gaps | Whitespace-only name rejection in PATCH channel, create/update org; case-insensitive email in lockout manager and invitation duplicate check |
| Rate limiting | Per-user email verification resend rate limit (429), SMTP failure error reporting (500 not false 200) |
| CORS | Wildcard origin `*` rejected when `AllowCredentials` is enabled |
| Transaction helpers | `CreateUser`, `CountUsers`, `UpdatePasswordHash`, `GetOrgByID` wrapped in `withBypassTx` |
| Invitation fixes | Duplicate pending check (409), cancel returns 404 if not found, nil org/inviter logging, audit entries for create/cancel/resend |
| Data lifecycle | `ListAllOrgs` excludes soft-deleted orgs (`WHERE deleted_at IS NULL`) |
| Config | Clear error when testing email channel without SMTP configured |

### Key implementation decisions

- **Per-batch (not per-task) subagent dispatch** — heavy file interdependencies (shared SQL files, sqlc regeneration ordering) would cause conflicts with per-task agents
- **429 for rate-limited resend** (not 200) — endpoint is authenticated, no anti-enumeration concern; distinct from password reset which uses 200 because it's unauthenticated
- **Bootstrap org failure non-fatal** — if `BootstrapFirstUserOrg` fails, user is still created and can log in; org can be created manually (B9 finding)
- **TOCTOU on invitation creation accepted** — `HasPendingInvitation` check-then-insert race is low risk (admin-only endpoint, narrow window, benign consequence)
- **sqlc `@param` syntax** — `lower(@email)` generates field name `Email` vs `lower($2)` which generates `Lower`

### Files changed

28 files, 1,120 insertions, 93 deletions across `internal/api/`, `internal/store/`, `internal/config/`

### Tests added

| Test | File | What it verifies |
|---|---|---|
| `TestLockout_CaseInsensitive` | `lockout_test.go` | Mixed-case emails count toward same lockout |
| `TestLockout_CleanupEvictsStaleEntries` | `lockout_test.go` | 100 stale entries evicted after TTL |
| `TestLockout_CleanupPreservesActiveLockouts` | `lockout_test.go` | Active lockouts survive cleanup |
| `TestResetPassword_ConcurrentUse` | `auth_password_reset_test.go` | Barrier pattern — exactly one of two concurrent resets succeeds |
| `TestResendVerification_RateLimit` | `auth_email_verification_test.go` | 429 after exceeding per-user token limit |
| `TestResendVerification_SMTPFailure` | `auth_email_verification_test.go` | 500 returned (not false 200) on SMTP failure |
| `TestCORSOrigins_WildcardRejected` | `cors_test.go` | Wildcard `*` filtered from origins |
| `TestCORSOrigins_WildcardAmongOthers` | `cors_test.go` | `*` filtered, valid origins preserved |
| `TestCORSMiddleware_WildcardReturnsNil` | `cors_test.go` | Middleware returns nil when only wildcard configured |
| `TestCORSOrigins_ValidOrigins` | `cors_test.go` | Non-wildcard origins pass through |
| `TestRegister_InviteOnly_ConcurrentBootstrap` | `auth_test.go` | Barrier pattern — concurrent bootstrap serialized by mutex |
| `TestAcceptInvitation_ConcurrentAccept` | `auth_test.go` | Barrier pattern — concurrent accept is idempotent |
| `TestPatchChannel_EmptyName_Rejected` | `channels_test.go` | Empty and whitespace-only names rejected (422) |
| `TestTestChannel_EmailNoSMTP` | `channels_test.go` | Clear error when SMTP not configured |
| `TestCreateOrg_WhitespaceName` | `orgs_test.go` | Whitespace-only name rejected |
| `TestUpdateOrg_WhitespaceName` | `orgs_test.go` | Whitespace-only name rejected |
| `TestCreateInvitation_DuplicatePending` | `orgs_test.go` | 409 on duplicate pending invitation |
| `TestCancelInvitation_NotFound` | `orgs_test.go` | 404 when invitation doesn't exist |

### Quality checks

- **go build ./...:** Clean
- **golangci-lint:** 0 issues
- **Unit tests:** 19/19 pass (lockout + CORS)
- **Integration tests:** Docker Desktop/testcontainers issue on Windows (pre-existing, not caused by changes)

---

## Phase 8A — Shared Foundation

**Branch:** None (landed directly on `dev`)
**Plan:** `dev/plans/2026-03-10-phase8-ops-phase8a-plan.md`
**PR:** #11 (bundled with code review fixes and documentation)

### What was built

5 tasks delivering foundational prerequisites that Phase 8B (Observe), 8C (Operate), and 8D (Extend) all depend on:

1. **`system_settings` migration (000034)** — System-level key-value table (`TEXT` PK, `BYTEA` value). NOT org-scoped, no RLS. Used by doctor encryption sentinel and CLI tools.
2. **`RequireSiteAdmin()` middleware verification** — Confirmed existing middleware is tested and correct. No new code.
3. **Security event type constants** (`internal/secure/events.go`) — 12 event type constants + 3 severity levels + `Severity()` lookup function with unexported `eventSeverity` map.
4. **Custom source precedence verification** (`internal/merge/resolve_custom_test.go`) — 4 tests codifying that `otherSources()` lets unknown source names contribute to union fields without winning scalar precedence. Added `IsReservedSourceName` helper in `internal/ingest/feeds.go`.
5. **Schema version bump** — `expectedSchemaVersion` from 30 to 34.

### Key decisions

- **Severity map unexported:** Initially exported `EventSeverity` map was refactored to unexported `eventSeverity` with a `Severity()` accessor function for cleaner encapsulation.
- **`system_settings` is NOT org-scoped:** No `org_id`, no RLS. Used only by site admins and CLI tools.
- **`IsReservedSourceName` is a semantic wrapper:** Delegates to `IsKnownFeed()` but provides a domain-meaningful name for config validation of custom feeds.

### Gotchas

- **gosec G101 false positives:** 3 `//nolint:gosec` suppressions needed on event constants containing "key", "token", "password" substrings (gosec thinks they're hardcoded credentials).
- **Schema version jump from 30 to 34:** Migrations 31-33 came from Phase 6/7 work before Phase 8A was planned.
- **No dedicated branch:** Phase 8A was intentionally a pre-gate on `dev`, bundled into PR #11 alongside code review fixes and documentation.

### Tests

| File | Tests |
|------|-------|
| `internal/secure/events_test.go` | 2 (`TestEventSeverityMapIsExhaustive`, `TestEventSeverityValues`) |
| `internal/merge/resolve_custom_test.go` | 4 (custom source CVSS, only-source, references union, packages union) |
| `internal/ingest/feeds_test.go` | 1 (`TestIsReservedSourceName`) |
| **Total** | **7** |

### Quality checks

- **go build ./...:** Clean
- **golangci-lint:** Clean (3 gosec false positives suppressed inline)

---

## Phase 8B — Observe Pillar

**Branch:** `phase-8b-observe` (worktree, concurrent with 8C/8D)
**Plan:** `dev/plans/2026-03-10-phase8-ops-observe-plan.md`
**PR:** #12 → merged to dev; #15 merged 8B/8C/8D to main

### What was built

5 batches across 19 tasks implementing the "Observe" pillar — Prometheus metrics across 6 subsystems, structured log correlation, separate metrics port, and Grafana dashboards:

1. **Metric definitions** (`internal/metrics/`) — 6 subsystem packages: HTTP (request counter + duration histogram), Feed (ingestion health), Alert (evaluation counters), Notification (delivery counters), Worker (job lifecycle), DB (pool collector via `PoolStatter` interface)
2. **Log correlation** (`internal/log/context.go`) — Context-aware slog helpers: `FromContext` fallback, `WithLogger` roundtrip, `Enrich` for adding fields. Request ID correlation middleware in `internal/api/log_middleware.go`
3. **Metrics port separation** — `/metrics` moved from main router to separate HTTP server on `METRICS_PORT` (default `9090`). Also added to standalone `worker` command
4. **Subsystem instrumentation** — Feed ingest handler, alert evaluator, notification worker, job pool, and DB pool collector all wired with metric calls. HTTP metrics middleware with cardinality-safe route labels
5. **Grafana dashboards & configs** — 3 dashboards (system overview, feed health, alerts & delivery) in `deploy/grafana/dashboards/`. Alerting rules in `deploy/grafana/alerts.yml`. Reference configs for Alloy and Prometheus

### Key decisions

- **DB Pool Collector uses `PoolStatter` interface:** Custom `PoolStats` struct instead of directly depending on `pgxpool.Stat`, with a pgxpool adapter for registration.
- **`statusWriter` includes `Unwrap()` method:** So `http.ResponseController` can discover `http.Flusher` and `http.Hijacker` on the underlying writer.
- **HTTP metrics middleware takes metrics as parameters:** `httpMetricsMiddleware(reqTotal, reqDuration)` rather than package-level vars — enables isolated-registry testing without cardinality collisions.
- **Retry-path metrics after DB write:** Moved per `tp§9.6` — metrics must reflect committed state, not optimistic state.

### Gotchas

- **Middleware ordering matters:** Review fix corrected ordering and added doc comments to metric vars.
- **`statusWriter` needed `Unwrap()`:** Required for compatibility with chi's response writer middleware chain.
- **Retry-path metrics placement:** Initially placed before `RetryDelivery` DB write, had to be moved after per testing-pitfalls §9.6.
- **Worker command also needs metrics:** The standalone `worker` cobra command needed its own metrics server + DB pool collector registration.

### Tests

| File | Tests |
|------|-------|
| `internal/metrics/*_test.go` | 6 (1 per subsystem) |
| `internal/log/context_test.go` | 3 (FromContext fallback, WithLogger roundtrip, Enrich) |
| `internal/api/log_middleware_test.go` | 1 |
| `internal/api/metrics_middleware_test.go` | 2 |
| `internal/api/metrics_server_test.go` | 1 |
| **Total** | **13** |

### Quality checks

- **go build ./...:** Clean
- **golangci-lint:** Clean (post-review fixes in `2bbec79`)
- **Go unit tests:** 13/13 pass across metrics, log, and API middleware packages

---

## Phase 8C — Operate Pillar

**Branch:** `phase-8c-operate` (worktree: `.worktrees/phase-8c-operate`)
**Plan:** `dev/plans/2026-03-10-ops-operate-plan.md`

### What was built

9 batches across 22 tasks implementing the "Operate" pillar:

1. **Health endpoints** — `/healthz` (liveness, no dependencies), `/readyz` (readiness: DB ping + migration check)
2. **Auto-migrate + version** — Advisory-locked auto-migration on `serve` startup; `/api/v1/admin/version` with ldflags injection
3. **Doctor framework** — `Check` interface, 9 health checks (DB connectivity, migration currency, DB role, RLS enforcement, encryption sentinel, JWT config, SMTP, disk, feed schedule), CLI `cvert-ops doctor` command, API endpoint
4. **Admin org/user management** — `disabled_at`/`locked_at`/`failed_login_count`/`force_password_reset` migration; admin list/patch/suspend/unsuspend orgs; admin list/disable/enable/unlock/reset-password users; disabled-user middleware check
5. **Admin feed/delivery/system** — Feed status with pause/resume/trigger; delivery list with retry/bulk-retry; audit log listing; config/doctor/version admin endpoints
6. **Docker production compose** — `compose.prod.yml` overlay with resource limits, log rotation, Caddy reverse proxy, production env defaults
7. **Admin UI** — 7 Vue pages (Dashboard, Orgs, Users, Feeds, Deliveries, Audit Log, System), route guard (`requiresAdmin`), sidebar guard (`isSiteAdmin`)
8. **Deployment docs** — 4 guides (getting-started, production, upgrading, TLS) + 4 runbooks (feed-failure, delivery-failure, db-recovery, upgrade-checklist)
9. **Final verification** — Go lint clean (except 3 pre-existing gosec false positives in `secure/events.go`), frontend build/lint/type-check/421 tests clean

### Key decisions

- **`sql.NullTime` → `*time.Time` in API-facing structs:** `sql.NullTime` serializes as `{"Time":"...","Valid":true}` not `null`. Created `fromNullTime()` converter pattern for all admin row types.
- **`adminOrgResponse` wrapper:** `generated.Organization` has no json tags (sqlc-generated). Created a separate response struct for the PATCH handler.
- **Caddy in Docker Compose:** Included as optional `--profile app` service for automatic ACME TLS. Not mandatory — operators can use nginx/ALB/etc.
- **Doctor `Check` interface:** Designed for extensibility — Secure pillar can register additional checks without modifying doctor core.
- **Auto-migrate advisory lock:** Uses `pg_advisory_lock(hashtext('cvert-ops-migrate'))` to prevent multiple instances from migrating concurrently.

### Gotchas

- **Select empty string value:** shadcn-vue `<SelectItem value="">` doesn't work — reka-ui requires non-empty `AcceptableValue`. Used `'all'` as sentinel and mapped to empty string in the fetch logic.
- **Pre-existing test failure:** `TestLoad_Defaults` in `config_test.go` expects `RegistrationMode` default `"open"` but code default is `"invite-only"`. Not introduced by this branch.
- **`-race` not available on Windows without CGO_ENABLED=1.** Integration tests (store, merge, notify) require Docker/testcontainers.

### Quality checks

- **go build ./...:** Clean
- **golangci-lint:** 3 pre-existing gosec false positives only
- **Frontend type-check:** Clean
- **Frontend lint (oxlint + eslint):** Clean
- **Frontend build (Vite):** Clean
- **Frontend tests (Vitest):** 421/421 pass across 32 test files
- **Go unit tests:** All Phase 8C packages pass (api, doctor, auth, crypto, tier, worker, secure, alert, cmd)

---

## Phase 8D — Extend Pillar

**Branch:** `phase-8d-extend` (worktree, concurrent with 8B/8C)
**Plan:** `dev/plans/2026-03-10-phase8-ops-extend-plan.md`
**PR:** #13 → merged to dev; #15 merged 8B/8C/8D to main

### What was built

7 batches across 15 tasks implementing the "Extend" pillar — config-driven generic feed adapters and an inbound webhook for custom CVE sources:

1. **Dependencies** — `tidwall/gjson` for JSON field mapping, `go.yaml.in/yaml/v4` for config parsing (not the archived `gopkg.in/yaml.v3`)
2. **Config system** (`internal/feed/generic/config.go`) — YAML config struct with validation (required fields, reserved name collision via `ingest.IsReservedSourceName`, cron expression checks), `LoadDir` for directory scanning, `Loader` struct with `Rescan()` for SIGHUP integration
3. **Generic feed adapter** (`internal/feed/generic/adapter.go`) — Implements `feed.Adapter`. JSON format with gjson field mapping, CSAF format via shared parser. 4 pagination strategies (none/offset/cursor/link-header), 4 auth types (none/bearer/basic/header with env-var credentials), rate limiting via `x/time/rate`, 50MB response cap, null byte sanitization
4. **Scheduler bridge** (`internal/feed/generic/scheduler.go`) — Converts generic configs to `ingest.FeedScheduleEntry` with cron-to-interval conversion. `AdapterFactory` wraps the built-in factory, creating generic adapters for known generic feed names and falling back to built-in adapters otherwise
5. **Inbound webhook** (`internal/api/ingest.go`) — `POST /api/v1/orgs/{org_id}/ingest` accepting CVE patches via JSON. Validates source name (non-reserved), CVE ID format, 100-patch limit. N patches consume N rate-limit tokens. Calls `merge.Ingest` per-patch independently. Returns 202 partial success or 400 if all rejected
6. **`validate-feeds` CLI** (`cmd/cvert-ops/validate.go`) — `cvert-ops validate-feeds` subcommand. Reads `CVERTOPS_FEEDS_DIR`, validates all YAML configs, reports errors. `--dry-run` flag stubbed for future connectivity testing
7. **Migration 000038** — Drops `cve_sources_source_name_check` constraint to allow custom feed names (validated at app layer via `IsReservedSourceName` instead)

### Key decisions

- **Timeout as string:** Config stores timeout as `string` (e.g., `"30s"`) rather than `time.Duration` — parsed at adapter creation time to avoid YAML marshaling issues with duration types.
- **Pagination raw count:** `nextPage` receives `rawCount` (before CVE ID filtering) to prevent filtered-out records from causing premature last-page detection.
- **Adapter factory wrapping:** Generic feeds don't modify `KnownFeeds` or `NewAdapter`. `AdapterFactory` wraps the built-in factory with a map lookup, cleanly separating generic from built-in feeds.
- **CSAF reuse:** CSAF format bypasses gjson mapping entirely and delegates to shared `csaf.Parse` — no mapping config needed for CSAF feeds.
- **Rate limit accounting on webhook:** N-1 additional tokens consumed (middleware already consumed 1 for the request itself).

### Gotchas

- **`cve_sources_source_name_check` constraint:** The Phase 7 migration hardcoded allowed source names. 8D's custom feeds need arbitrary names → migration 000038 drops the constraint in favor of app-layer validation.
- **Cursor URL encoding:** Cursor values from upstream APIs needed URL encoding when interpolated into pagination URLs (commit `9aa4be0`).
- **CSAF null bytes:** CSAF advisory strings contained null bytes that needed sanitization before database insertion (commit `9aa4be0`).
- **Empty CVE IDs:** Some records had no CVE ID — needed to be filtered rather than producing empty patches (commit `9aa4be0`).
- **Config test default mismatch:** Test assumed `RegistrationMode` default `"open"` but code default is `"invite-only"` (pre-existing, commit `b0ad824`).

### Tests

| File | Tests |
|------|-------|
| `internal/feed/generic/adapter_test.go` | 23 |
| `internal/feed/generic/config_test.go` | 20 |
| `internal/feed/generic/scheduler_test.go` | 3 |
| `internal/api/ingest_test.go` | 11 |
| `cmd/cvert-ops/validate_test.go` | 6 |
| **Total** | **63** |

### Quality checks

- **go build ./...:** Clean
- **golangci-lint:** Clean (post-review fixes in `a9a2bb2`)
- **Go unit tests:** 63/63 pass across generic feed, ingest, and validate packages
- **Post-merge fix:** `d17460e` resolved integration issues from 8B/8C/8D merge

---

## Phase 8E — Secure Pillar

> **Date:** 2026-03-16
> **Branch:** `phase8e-secure` → merged via PR #43
> **Plan:** `dev/plans/2026-03-16-phase8-ops-secure-v2-plan.md`

### What was built

Security operations infrastructure: dual-key JWT rotation for zero-downtime secret
rotation, dual-key SSO encryption rotation with `DecryptWithFallback`, SIGHUP-based
config hot-reload with `ReloadableConfig` (atomic pointer), `rotate-encryption-key`
CLI command, `POST /admin/reload-config` endpoint, security events pipeline (async writer
with rate limiting, syslog/SIEM output, `security_events` table + migration),
`GET /admin/security-events` endpoint with cursor pagination, security event wiring
into auth/admin handlers, doctor security checks (headers, SSRF, CORS, JWT dual-key),
Prometheus metrics for the security event pipeline, security_events retention cleanup
(90-day default), and a secret rotation runbook.

### Files created/modified

| File | Action | Batch |
|------|--------|-------|
| `internal/auth/jwt.go` | Modified | 1 |
| `internal/auth/jwt_test.go` | Modified | 1 |
| `internal/config/config.go` | Modified | 1, 3 |
| `internal/api/auth.go` | Modified | 1 |
| `internal/api/middleware_auth.go` | Modified | 1 |
| `internal/crypto/aes.go` | Modified | 2 |
| `internal/crypto/aes_test.go` | Modified | 2 |
| `internal/api/sso.go` | Modified | 2 |
| `cmd/cvert-ops/rotate.go` | Created | 2 |
| `cmd/cvert-ops/rotate_test.go` | Created | 2 |
| `internal/config/reloadable.go` | Created | 3 |
| `internal/config/reloadable_test.go` | Created | 3 |
| `internal/config/reload.go` | Created | 3 |
| `internal/config/reload_test.go` | Created | 3 |
| `internal/config/sighup_unix.go` | Created | 3 |
| `internal/config/sighup_windows.go` | Created | 3 |
| `internal/api/admin_reload.go` | Created | 3 |
| `internal/api/admin_reload_test.go` | Created | 3 |
| `migrations/000039_create_security_events.up.sql` | Created | 4 |
| `migrations/000039_create_security_events.down.sql` | Created | 4 |
| `internal/store/security_events.go` | Created | 4 |
| `internal/store/queries/security_events.sql` | Created | 4 |
| `internal/secure/writer.go` | Created | 4 |
| `internal/secure/writer_test.go` | Created | 4 |
| `internal/secure/ratelimit.go` | Created | 4 |
| `internal/secure/ratelimit_test.go` | Created | 4 |
| `internal/secure/syslog.go` | Created | 4 |
| `internal/secure/syslog_test.go` | Created | 4 |
| `internal/api/admin_security_events.go` | Created | 4 |
| `internal/api/admin_security_events_test.go` | Created | 4 |
| `internal/doctor/checks.go` | Modified | 5 |
| `internal/doctor/doctor_test.go` | Modified | 5 |
| `internal/metrics/security.go` | Created | 6 |
| `internal/metrics/security_test.go` | Created | 6 |
| `deploy/grafana/alerts.yml` | Modified | 6 |
| `docs/deployment/runbooks/secret-rotation.md` | Created | 6 |
| `internal/retention/runner.go` | Modified | 4 |
| `internal/retention/runner_test.go` | Modified | 4 |
| `internal/store/retention.go` | Modified | 4 |
| `internal/store/retention_test.go` | Modified | 4 |

### Key implementation decisions

1. **Dual-key JWT verification**: `ParseWithDualKey` tries the current secret first, falls
   back to `JWT_SECRET_PREVIOUS`. Enables zero-downtime secret rotation — old tokens remain
   valid until they expire naturally.

2. **`DecryptWithFallback` for SSO encryption**: Tries current AES key, falls back to
   `SSO_ENCRYPTION_KEY_PREVIOUS`. SSO state tokens encrypted at rest can be decrypted during
   key rotation window.

3. **ReloadableConfig with `atomic.Pointer`**: Thread-safe config hot-reload without restart.
   `SIGHUP` handler (Unix) or `POST /admin/reload-config` (all platforms) triggers reload.
   Only secret fields are reloadable — structural config changes still require restart.

4. **Async security event writer**: Non-blocking channel-based writer with configurable
   buffer size. Rate limiter prevents event storms from saturating the DB. Events are
   batched and flushed periodically.

5. **Syslog SIEM integration**: RFC 5424 syslog output for security events. Configurable
   facility/severity mapping. Supports both UDP and TCP transports.

6. **Security events retention**: 90-day default retention for `security_events` table,
   integrated into the existing retention cleanup runner.

### Gotchas discovered

- **Windows SIGHUP**: Windows has no SIGHUP signal — `sighup_windows.go` is a no-op stub.
  Config reload on Windows is only available via the HTTP endpoint.
- **Phase 8E took migration 000039**: This caused a numbering collision with the MFA plan
  (which also planned for 000039), requiring MFA tables to be renumbered to 000040.

### Quality checks

- **go build ./...:** Clean
- **golangci-lint:** Clean
- **All tests pass** across auth, config, crypto, secure, doctor, metrics, retention packages
- **3 review rounds** with 4 parallel code-reviewer agents (findings documented in plan)

---

## Phase 11 — MFA: TOTP + Email OTP

> **Date:** 2026-03-16 – 2026-03-17
> **Branches:** `worktree-phase11-mfa` (Tasks 1-9, PR #44) → `phase11-mfa-handlers` (Tasks 10-24, PR #50)
> **Plan:** `dev/plans/2026-03-16-phase11-mfa-totp-email-otp-plan.md`

### What was built

Complete MFA system: config fields, database migration (4 new tables + 3 org columns),
`pquerna/otp` TOTP dependency, store CRUD for credentials/recovery codes/challenges/requirements,
3-layer MFA mandate check, pending JWT tokens for restricted sessions, MFA challenge/verify
login flow, TOTP and email OTP enrollment, MFA management (list/remove methods, regenerate
recovery codes), remember-device, admin MFA reset, admin force-password-reset, per-member
MFA requirements, org-wide MFA settings, middleware MFA route gating, restricted password
change, security events, periodic challenge cleanup worker, and full end-to-end integration tests.

### Files created/modified

| File | Action | Tasks |
|------|--------|-------|
| `internal/config/config.go` | Modified | 1 |
| `internal/config/config_test.go` | Modified | 1 |
| `migrations/000040_create_mfa_tables.up.sql` | Created | 2 |
| `migrations/000040_create_mfa_tables.down.sql` | Created | 2 |
| `go.mod` / `go.sum` | Modified | 3 |
| `internal/store/queries/mfa.sql` | Created | 4-8 |
| `internal/store/generated/mfa.sql.go` | Generated | 4-8 |
| `internal/store/mfa.go` | Created | 4-8 |
| `internal/store/mfa_test.go` | Created | 4-8 |
| `internal/auth/jwt.go` | Modified | 9 |
| `internal/auth/jwt_test.go` | Modified | 9 |
| `internal/api/auth_mfa.go` | Created | 10-15, 20-21 |
| `internal/api/auth_mfa_test.go` | Created | 10-15, 20 |
| `internal/api/auth_mfa_integration_test.go` | Created | 23 |
| `internal/api/admin_mfa.go` | Created | 18-19, 21 |
| `internal/api/admin_mfa_test.go` | Created | 18-19 |
| `internal/api/auth.go` | Modified | 10, 17, 21 |
| `internal/api/auth_test.go` | Modified | 24 (fix) |
| `internal/api/middleware_auth.go` | Modified | 16 |
| `internal/secure/events.go` | Modified | 21 |
| `internal/secure/events_test.go` | Modified | 21 |
| `internal/worker/pool.go` | Modified | 22 |
| `cmd/cvert-ops/main.go` | Modified | 22 |
| `dev/testing-pitfalls.md` | Modified | review |

### Key implementation decisions

1. **Migration renumbered 000039 → 000040**: Phase 8E's secure-pillar migration landed on
   `dev` as 000039 after the MFA plan was written. Renumbered to avoid collision.

2. **4 global tables + 1 org-scoped**: `mfa_credentials`, `mfa_recovery_codes`, `mfa_challenges`
   are global (no RLS) — checked at login before org context is established. `mfa_requirements`
   is org-scoped with RLS policy matching the standard `app.org_id` / `app.bypass_rls` pattern.

3. **3-layer MFA mandate check** (`IsMFAMandated`): Checks site config → org `mfa_required_all`
   → per-member `mfa_requirements` row. Uses `withBypassTx` since it runs at login time.

4. **Recovery code design**: 8 codes per set, stored as argon2id hashes. Verification uses
   `SELECT FOR UPDATE SKIP LOCKED` to prevent double-consumption under concurrent requests.

5. **Pending JWT tokens**: `PendingClaims` carries a `Pending []string` array (e.g.,
   `["mfa_challenge", "password_reset"]`). Short-lived (5min default). Separate `EnrollmentClaims`
   for the `mfa_enrollment_required` flow. Both enforce `WithValidMethods` + `WithExpirationRequired`.

6. **TOTP secret encryption**: AES-256-GCM via `internal/crypto`. Database CHECK constraint
   enforces `secret_enc IS NOT NULL` for TOTP and `IS NULL` for email OTP.

7. **Dual-auth for enrollment endpoints**: `resolveEnrollmentUserID` accepts both
   `access_token` (authenticated users) and `mfa_pending_token` (users with
   `mfa_enrollment_required`). Enables mandated enrollment without full access.

8. **Single `time.Now()` for TOTP**: Captures `now` once for both validation and step
   calculation to prevent clock-boundary race across a 30-second boundary.

9. **Worker pool PeriodicTask**: Added `PeriodicTask` type to `worker.Pool` for fixed-interval
   tasks alongside job queue polling. Uses `time.NewTicker` with `defer ticker.Stop()`.

10. **Security event pipeline**: `eventWriter.Write(ctx, secure.Event{...})` for both huma
    and chi handlers. 22 MFA event constants with severity mappings.

11. **Fail-closed MFA enforcement**: `buildMFARequiredReasons` returns `["db_error"]` when
    DB checks fail, preventing false "not required" results from masking a mandate.

12. **RBAC hierarchy for admin MFA actions**: Owner can target admin/member, admin can target
    member only, site admin can target anyone. Self-target blocked with 400.

### Gotchas discovered

- **Migration numbering conflicts**: Concurrent branches cause collisions. Fix was a rename
  (no SQL changes) after merging `dev`.
- **`pquerna/otp` verified active**: Web-searched before adding — last release 2024, widely used.
- **`//nolint` inside function call args**: `replace_all` placed nolint comments inside
  Go function call argument lists, breaking syntax. Must extract to local variable first.
- **gosec G104 vs errcheck**: golangci-lint v2 `//nolint:errcheck` doesn't suppress
  gosec G104 — need `//nolint:errcheck,gosec` in test files.
- **Huma vs chi auth**: Huma routes use cookie-based auth from input structs; chi routes
  use `RequireAuthenticated()` middleware which also handles Bearer API keys. API key
  tests must target chi routes.
- **Test broken by MFA changes**: `TestMe_IncludesForcePasswordReset` assumed login still
  issues access tokens with `force_password_reset`. Updated to check `pending` field directly.

### Quality checks

- **go build ./...:** Clean
- **golangci-lint:** Clean
- **Store tests:** All pass (credentials, recovery codes, challenges, requirements, mandate check)
- **JWT tests:** PendingClaims and EnrollmentClaims round-trip tests pass
- **MFA handler tests:** 44/44 pass (unit + integration)
- **Integration tests:** 8 end-to-end flows covering TOTP, email OTP, recovery codes,
  forced password reset, enrollment mandate, password reset MFA bypass prevention,
  API key MFA bypass, concurrent recovery code race condition
- **RBAC edge case tests:** Self-target (400) and same-level (403) rejection verified
- **Post-review cleanup** (PR #44): Fixed ABOUTME comments, removed dead imports,
  added RLS store tests for `mfa_requirements`

---
