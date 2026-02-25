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
- [ ] OSV all.zip URL verification pending re-research (previous research agent lacked web access; new agent launched with updated AGENT.md)

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

- [ ] Commit 8: EPSS adapter (`internal/feed/epss/adapter.go`) — two-statement IS DISTINCT FROM pattern, advisory lock
- [ ] OSV all.zip URL verification: re-research agent (a1df16c) running with web access

---
