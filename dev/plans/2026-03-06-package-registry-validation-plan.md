# Package Registry Validation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for every task -- write failing tests first, verify failure, implement, verify pass.

**Goal:** Validate watchlist package entries against public registries asynchronously, surfacing a `registry_status` badge in the UI to warn users about typos without blocking saves.

**Architecture:** Soft validation -- never block item creation. When a package item is created, the API handler enqueues a `registry_validate` job. A background worker claims the job, calls the appropriate registry API, and writes the result back to `watchlist_items.registry_status`. The API always returns `registry_status` in responses; the frontend shows a warning badge for non-verified items. Registry clients implement a common `Checker` interface with per-ecosystem rate limiting.

**Tech Stack:** Go 1.26, PostgreSQL 15+, sqlc, golang-migrate, `golang.org/x/time/rate`, `net/http`, Vue 3, shadcn-vue

**Phase:** 2+ (not urgent -- document for future implementation)

---

## Background & Design Decisions

- **PURL compatibility:** Watchlist items already store `(ecosystem, package_name, namespace)` which maps to PURL `pkg:ecosystem/namespace/name`. No schema change needed for the identifier model.
- **Soft validation only:** Users must never be blocked from saving. Validation is advisory.
- **Status enum:** `pending` (just created, not yet checked), `verified` (registry confirmed), `unverified` (registry returned 404), `unknown_registry` (ecosystem has no checker implemented), `skipped` (private/namespaced package where validation is impossible).
- **Priority ecosystems:** npm, PyPI, crates.io, RubyGems (highest CVE volume, friendliest APIs). Go proxy has a 404-for-never-proxied caveat making it unreliable; Maven Central needs two-part coordinates. Both are deferred.
- **Rate limiting:** Per-ecosystem `rate.Limiter` injected into each checker. RubyGems is the tightest at 10 req/s.
- **Private packages:** Cannot validate without user credentials. Auto-set `skipped` for ecosystems where namespace suggests private scope (e.g., `@company/` in npm).

---

### Task 1: Database Migration -- Add `registry_status` to `watchlist_items`

Add a new enum type and column to `watchlist_items`. Default is `'pending'` for package items, `'skipped'` for CPE items (CPE items are not registry-validated).

**Files:**
- Create: `migrations/000029_watchlist_registry_status.up.sql`
- Create: `migrations/000029_watchlist_registry_status.down.sql`

**Step 1: Write the up migration**

```sql
-- migrate:no-transaction
-- CONCURRENTLY indexes cannot run inside a transaction block.

CREATE TYPE registry_status AS ENUM (
    'pending',
    'verified',
    'unverified',
    'unknown_registry',
    'skipped'
);

-- Add column with a default that depends on item_type.
-- For existing rows: packages get 'pending', CPEs get 'skipped'.
ALTER TABLE watchlist_items
    ADD COLUMN registry_status registry_status NOT NULL DEFAULT 'pending';

-- Backfill CPE items to 'skipped' since they don't go through registry validation.
UPDATE watchlist_items
SET registry_status = 'skipped'
WHERE item_type = 'cpe';

-- Index for the worker to find pending items efficiently.
CREATE INDEX CONCURRENTLY IF NOT EXISTS watchlist_items_registry_pending_idx
    ON watchlist_items (registry_status)
    WHERE registry_status = 'pending' AND deleted_at IS NULL;
```

**Step 2: Write the down migration**

```sql
-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS watchlist_items_registry_pending_idx;
ALTER TABLE watchlist_items DROP COLUMN IF EXISTS registry_status;
DROP TYPE IF EXISTS registry_status;
```

**Step 3: Run migration locally**

Run: `go run ./cmd/cvert-ops migrate`
Expected: Migration 000029 applied successfully.

**Step 4: Verify rollback works**

Run: `migrate -path migrations -database "$DATABASE_URL" down 1`
Expected: Migration 000029 rolled back. Column and type removed.

Re-apply: `go run ./cmd/cvert-ops migrate`

**Step 5: Commit**

```bash
git add migrations/000029_watchlist_registry_status.up.sql migrations/000029_watchlist_registry_status.down.sql
git commit -m "migration: add registry_status column to watchlist_items"
```

---

### Task 2: Regenerate sqlc and Update Store Types

After the migration, regenerate sqlc so `WatchlistItem` includes `registry_status`. Update the store layer's `ListWatchlistItems` squirrel query to include the new column.

**Files:**
- Modify: `internal/store/queries/watchlist.sql` (add UpdateRegistryStatus query, add ListPendingRegistryItems query)
- Regenerate: `internal/store/generated/watchlist.sql.go`
- Modify: `internal/store/watchlist.go` (update ListWatchlistItems scan, add UpdateRegistryStatus, add ListPendingRegistryItems)

**Step 1: Add sqlc queries**

Add to `internal/store/queries/watchlist.sql`:

```sql
-- name: UpdateWatchlistItemRegistryStatus :exec
UPDATE watchlist_items
SET registry_status = $4
WHERE id = $1 AND watchlist_id = $2 AND org_id = $3 AND deleted_at IS NULL;

-- name: ListPendingRegistryItems :many
-- Finds package items needing registry validation. Used by the background worker.
-- Processes in FIFO order (oldest first) with a limit to control batch size.
SELECT * FROM watchlist_items
WHERE registry_status = 'pending'
  AND item_type = 'package'
  AND deleted_at IS NULL
ORDER BY created_at ASC
LIMIT $1;
```

**Step 2: Regenerate sqlc**

Run: `sqlc generate`
Expected: `internal/store/generated/watchlist.sql.go` regenerated with new `RegistryStatus` field on `WatchlistItem` and new query functions.

**Step 3: Update ListWatchlistItems scan in `internal/store/watchlist.go`**

The squirrel-based `ListWatchlistItems` manually scans columns. Add `wi.registry_status` to the SELECT list and the `Scan` call. The exact column list becomes:

```go
sb := psql.Select(
    "wi.id, wi.watchlist_id, wi.org_id, wi.item_type, wi.ecosystem, wi.package_name, wi.namespace, wi.cpe_normalized, wi.registry_status, wi.created_at, wi.deleted_at",
).
```

And in the scan:

```go
if err := rows.Scan(
    &item.ID, &item.WatchlistID, &item.OrgID, &item.ItemType,
    &item.Ecosystem, &item.PackageName, &item.Namespace, &item.CpeNormalized,
    &item.RegistryStatus, &item.CreatedAt, &item.DeletedAt,
); err != nil {
```

**Step 4: Add store wrapper methods**

Add to `internal/store/watchlist.go`:

```go
// UpdateWatchlistItemRegistryStatus sets the registry_status for a specific item.
// Used by the registry validation worker after checking the package registry.
func (s *Store) UpdateWatchlistItemRegistryStatus(ctx context.Context, orgID, watchlistID, itemID uuid.UUID, status generated.RegistryStatus) error {
    return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
        return q.UpdateWatchlistItemRegistryStatus(ctx, generated.UpdateWatchlistItemRegistryStatusParams{
            ID:             itemID,
            WatchlistID:    watchlistID,
            OrgID:          orgID,
            RegistryStatus: status,
        })
    })
}

// ListPendingRegistryItems returns up to limit package items that need registry validation.
// Called by the background worker -- uses bypass RLS since it scans across orgs.
func (s *Store) ListPendingRegistryItems(ctx context.Context, limit int) ([]generated.WatchlistItem, error) {
    var items []generated.WatchlistItem
    err := s.withBypassTx(ctx, func(q *generated.Queries) error {
        var err error
        items, err = q.ListPendingRegistryItems(ctx, int32(limit))
        return err
    })
    return items, err
}
```

**Step 5: Add to WatchlistStore interface**

Add `UpdateWatchlistItemRegistryStatus` to the `WatchlistStore` interface in `internal/store/watchlist.go`.

**Step 6: Run tests**

Run: `go test ./internal/store/ -run TestWatchlist -v`
Expected: Existing tests pass (they'll need scan updates if they check column counts, but sqlc-generated code handles this).

**Step 7: Commit**

```bash
git add internal/store/queries/watchlist.sql internal/store/generated/ internal/store/watchlist.go
git commit -m "feat: add registry_status to watchlist items store layer"
```

---

### Task 3: Checker Interface and npm Implementation

Define the `Checker` interface and implement the first checker (npm). This is a pure HTTP client with rate limiting -- no database access.

**Files:**
- Create: `internal/registry/checker.go` (interface + types)
- Create: `internal/registry/npm.go`
- Create: `internal/registry/npm_test.go`

**Step 1: Write the failing test for npm checker**

```go
// internal/registry/npm_test.go
package registry_test

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/scarson/cvert-ops/internal/registry"
)

func TestNpmChecker_Exists(t *testing.T) {
    t.Parallel()

    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/lodash/latest" {
            t.Errorf("unexpected path: %s", r.URL.Path)
        }
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"name":"lodash"}`))
    }))
    defer srv.Close()

    c := registry.NewNpmChecker(srv.Client(), srv.URL)
    result, err := c.Check(context.Background(), "lodash", "")
    if err != nil {
        t.Fatalf("Check: %v", err)
    }
    if result != registry.StatusVerified {
        t.Errorf("got %s, want %s", result, registry.StatusVerified)
    }
}

func TestNpmChecker_NotFound(t *testing.T) {
    t.Parallel()

    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusNotFound)
    }))
    defer srv.Close()

    c := registry.NewNpmChecker(srv.Client(), srv.URL)
    result, err := c.Check(context.Background(), "nonexistent-pkg-xyz", "")
    if err != nil {
        t.Fatalf("Check: %v", err)
    }
    if result != registry.StatusUnverified {
        t.Errorf("got %s, want %s", result, registry.StatusUnverified)
    }
}

func TestNpmChecker_ScopedPackage(t *testing.T) {
    t.Parallel()

    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // npm scoped packages encode the slash: @scope%2Fpkg
        if r.URL.Path != "/@angular%2Fcore/latest" && r.URL.Path != "/@angular/core/latest" {
            t.Errorf("unexpected path: %s", r.URL.Path)
        }
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"name":"@angular/core"}`))
    }))
    defer srv.Close()

    c := registry.NewNpmChecker(srv.Client(), srv.URL)
    result, err := c.Check(context.Background(), "core", "@angular")
    if err != nil {
        t.Fatalf("Check: %v", err)
    }
    if result != registry.StatusVerified {
        t.Errorf("got %s, want %s", result, registry.StatusVerified)
    }
}

func TestNpmChecker_ServerError_ReturnsError(t *testing.T) {
    t.Parallel()

    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusInternalServerError)
    }))
    defer srv.Close()

    c := registry.NewNpmChecker(srv.Client(), srv.URL)
    _, err := c.Check(context.Background(), "lodash", "")
    if err == nil {
        t.Fatal("expected error on 500 response")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/registry/ -run TestNpmChecker -v`
Expected: FAIL -- package does not exist.

**Step 3: Write the interface and npm implementation**

`internal/registry/checker.go`:
```go
// ABOUTME: Interface and types for package registry validation.
// ABOUTME: Each ecosystem implements Checker to verify packages exist in public registries.
package registry

import "context"

// Status represents the outcome of a registry validation check.
type Status string

const (
    StatusVerified        Status = "verified"
    StatusUnverified      Status = "unverified"
    StatusUnknownRegistry Status = "unknown_registry"
    StatusSkipped         Status = "skipped"
    StatusPending         Status = "pending"
)

// Checker validates whether a package exists in a public registry.
// name is the package name, namespace is the optional scope/org prefix
// (e.g., "@angular" for npm).
// Returns a Status and an error. Transient errors (network, rate limit, 5xx)
// return non-nil error so the caller can retry. A definitive 404 returns
// (StatusUnverified, nil).
type Checker interface {
    Check(ctx context.Context, name, namespace string) (Status, error)
    Ecosystem() string
}
```

`internal/registry/npm.go`:
```go
// ABOUTME: npm registry checker -- verifies packages exist on registry.npmjs.org.
// ABOUTME: Handles scoped packages (@scope/name) and rate-limit-safe GET requests.
package registry

import (
    "context"
    "fmt"
    "net/http"
    "net/url"
)

// NpmChecker validates package names against the npm public registry.
type NpmChecker struct {
    client  *http.Client
    baseURL string
}

// NewNpmChecker creates an npm registry checker. Pass a custom baseURL for testing;
// production uses "https://registry.npmjs.org".
func NewNpmChecker(client *http.Client, baseURL string) *NpmChecker {
    return &NpmChecker{client: client, baseURL: baseURL}
}

func (c *NpmChecker) Ecosystem() string { return "npm" }

func (c *NpmChecker) Check(ctx context.Context, name, namespace string) (Status, error) {
    // Build the package identifier. Scoped packages: @scope/name
    pkgName := name
    if namespace != "" {
        pkgName = namespace + "/" + name
    }

    reqURL := c.baseURL + "/" + url.PathEscape(pkgName) + "/latest"
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
    if err != nil {
        return "", fmt.Errorf("npm check: build request: %w", err)
    }
    req.Header.Set("Accept", "application/json")

    resp, err := c.client.Do(req)
    if err != nil {
        return "", fmt.Errorf("npm check: %w", err)
    }
    defer resp.Body.Close()

    switch {
    case resp.StatusCode == http.StatusOK:
        return StatusVerified, nil
    case resp.StatusCode == http.StatusNotFound:
        return StatusUnverified, nil
    default:
        return "", fmt.Errorf("npm check: unexpected status %d for %s", resp.StatusCode, pkgName)
    }
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/registry/ -run TestNpmChecker -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/registry/
git commit -m "feat: add Checker interface and npm implementation"
```

---

### Task 4: PyPI, crates.io, and RubyGems Checkers

Implement the remaining priority ecosystem checkers following the same pattern.

**Files:**
- Create: `internal/registry/pypi.go`
- Create: `internal/registry/pypi_test.go`
- Create: `internal/registry/crates.go`
- Create: `internal/registry/crates_test.go`
- Create: `internal/registry/rubygems.go`
- Create: `internal/registry/rubygems_test.go`

**Step 1: Write failing tests for all three checkers**

Each test file follows the same pattern as the npm tests: `httptest.NewServer`, test exists (200 -> verified), test not found (404 -> unverified), test server error (5xx -> error).

Key registry-specific details for the implementations:

**PyPI** (`pypi.org/simple/{name}/`):
- URL: `GET {baseURL}/simple/{name}/`
- 200 = exists, 404 = not found
- No namespace support (PyPI packages are flat)
- Normalize name: replace `_`, `-`, `.` with `-`, lowercase (PEP 503)

**crates.io** (`index.crates.io`):
- URL: `GET {baseURL}/{prefix}/{name}` where prefix is computed from name length:
  - 1 char: `1/{name}`
  - 2 chars: `2/{name}`
  - 3 chars: `3/{first_char}/{name}`
  - 4+ chars: `{first_two}/{next_two}/{name}`
- 200 = exists, 404/403 = not found
- Name is lowercased

**RubyGems** (`rubygems.org/api/v1/gems/{name}.json`):
- URL: `GET {baseURL}/api/v1/gems/{name}.json`
- 200 = exists, 404 = not found
- 10 req/s rate limit (handle via caller-side `rate.Limiter`)

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/registry/ -v`
Expected: FAIL -- types/functions not defined

**Step 3: Implement all three checkers**

Each follows the same structure as `NpmChecker`: constructor takes `*http.Client` + `baseURL`, `Check` method builds URL, makes GET request, returns status based on HTTP response code.

**PyPI-specific:** Add a `normalizePyPIName(name string) string` helper that replaces `[-_.]+` with `-` and lowercases. Test this helper explicitly.

**crates.io-specific:** Add a `crateIndexPrefix(name string) string` helper that computes the sparse index path prefix. Test this helper explicitly with names of length 1, 2, 3, and 4+.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/registry/ -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add internal/registry/
git commit -m "feat: add PyPI, crates.io, and RubyGems registry checkers"
```

---

### Task 5: Checker Resolver (Ecosystem -> Checker Routing)

Create a resolver that maps ecosystem names to their `Checker` implementation, with rate-limited HTTP clients per ecosystem.

**Files:**
- Create: `internal/registry/resolver.go`
- Create: `internal/registry/resolver_test.go`
- Create: `internal/registry/transport.go`

**Step 1: Write failing test**

```go
func TestResolver_KnownEcosystem(t *testing.T) {
    t.Parallel()
    r := registry.NewResolver(http.DefaultClient)

    checker, ok := r.Get("npm")
    if !ok {
        t.Fatal("expected npm checker to be registered")
    }
    if checker.Ecosystem() != "npm" {
        t.Errorf("got ecosystem %q, want npm", checker.Ecosystem())
    }
}

func TestResolver_UnknownEcosystem(t *testing.T) {
    t.Parallel()
    r := registry.NewResolver(http.DefaultClient)

    _, ok := r.Get("obscure-lang-pkg")
    if ok {
        t.Fatal("expected unknown ecosystem to return false")
    }
}

func TestResolver_AllSupportedEcosystems(t *testing.T) {
    t.Parallel()
    r := registry.NewResolver(http.DefaultClient)

    for _, eco := range []string{"npm", "pypi", "cargo", "rubygems"} {
        checker, ok := r.Get(eco)
        if !ok {
            t.Errorf("expected %s checker to be registered", eco)
            continue
        }
        if checker.Ecosystem() != eco {
            t.Errorf("checker.Ecosystem() = %q, want %q", checker.Ecosystem(), eco)
        }
    }
}
```

**Step 2: Run to verify failure, then implement**

`internal/registry/transport.go`:
```go
// ABOUTME: Rate-limited HTTP RoundTripper for registry API calls.
// ABOUTME: Wraps an existing client's transport with a token-bucket rate limiter.
package registry

import (
    "net/http"

    "golang.org/x/time/rate"
)

type rateLimitedTransport struct {
    base    http.RoundTripper
    limiter *rate.Limiter
}

func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    if err := t.limiter.Wait(req.Context()); err != nil {
        return nil, err
    }
    return t.base.RoundTrip(req)
}

// rateLimitedClient creates a shallow copy of the client with a rate-limited transport.
func rateLimitedClient(base *http.Client, limiter *rate.Limiter) *http.Client {
    transport := base.Transport
    if transport == nil {
        transport = http.DefaultTransport
    }
    return &http.Client{
        Transport: &rateLimitedTransport{base: transport, limiter: limiter},
        Timeout:   base.Timeout,
    }
}
```

`internal/registry/resolver.go`:
```go
// ABOUTME: Routes ecosystem names to their Checker implementation.
// ABOUTME: Initializes per-ecosystem rate-limited HTTP clients.
package registry

import (
    "net/http"

    "golang.org/x/time/rate"
)

// Resolver maps ecosystem names to their registry Checker.
type Resolver struct {
    checkers map[string]Checker
}

// NewResolver creates a Resolver with all supported ecosystem checkers.
// The provided client is used as the base transport; per-ecosystem rate
// limiting is applied via a rate.Limiter-wrapping RoundTripper.
func NewResolver(client *http.Client) *Resolver {
    r := &Resolver{checkers: make(map[string]Checker)}

    // npm: undocumented limits, use 20 req/s as safe default
    r.checkers["npm"] = NewNpmChecker(
        rateLimitedClient(client, rate.NewLimiter(20, 5)),
        "https://registry.npmjs.org",
    )
    // PyPI: CDN-cached, generous limits
    r.checkers["pypi"] = NewPyPIChecker(
        rateLimitedClient(client, rate.NewLimiter(50, 10)),
        "https://pypi.org",
    )
    // crates.io: sparse index, no documented rate limit
    r.checkers["cargo"] = NewCratesChecker(
        rateLimitedClient(client, rate.NewLimiter(30, 10)),
        "https://index.crates.io",
    )
    // RubyGems: 10 req/s load-balancer cap -- use 8 req/s with burst 3
    r.checkers["rubygems"] = NewRubyGemsChecker(
        rateLimitedClient(client, rate.NewLimiter(8, 3)),
        "https://rubygems.org",
    )

    return r
}

// Get returns the Checker for the given ecosystem, or (nil, false) if unsupported.
func (r *Resolver) Get(ecosystem string) (Checker, bool) {
    c, ok := r.checkers[ecosystem]
    return c, ok
}

// Checkers returns the internal map for use by the validation worker.
func (r *Resolver) Checkers() map[string]Checker {
    return r.checkers
}
```

**Step 3: Run tests**

Run: `go test ./internal/registry/ -v`
Expected: All PASS

**Step 4: Commit**

```bash
git add internal/registry/
git commit -m "feat: add registry checker resolver with rate-limited transports"
```

---

### Task 6: Registry Validation Worker Handler

Create the worker handler that processes `registry_validate` jobs. The handler:
1. Deserializes the job payload (item ID, org ID, watchlist ID, ecosystem, package name, namespace)
2. Looks up the appropriate `Checker` via the ecosystem name
3. Calls `Check` and writes the result back via `UpdateWatchlistItemRegistryStatus`

**Files:**
- Create: `internal/registry/handler.go`
- Create: `internal/registry/handler_test.go`

**Step 1: Write failing test**

```go
func TestValidationHandler_VerifiedPackage(t *testing.T) {
    t.Parallel()

    // Fake registry server returns 200
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))
    defer srv.Close()

    fakeStore := &fakeRegistryStore{}
    checker := registry.NewNpmChecker(srv.Client(), srv.URL)
    handler := registry.NewValidationHandler(fakeStore, map[string]registry.Checker{"npm": checker})

    payload := []byte(`{
        "item_id": "00000000-0000-0000-0000-000000000001",
        "org_id": "00000000-0000-0000-0000-000000000002",
        "watchlist_id": "00000000-0000-0000-0000-000000000003",
        "ecosystem": "npm",
        "package_name": "lodash",
        "namespace": ""
    }`)

    err := handler.Handle(context.Background(), payload)
    if err != nil {
        t.Fatalf("Handle: %v", err)
    }

    if fakeStore.lastStatus != "verified" {
        t.Errorf("expected verified, got %s", fakeStore.lastStatus)
    }
}

func TestValidationHandler_UnknownEcosystem(t *testing.T) {
    t.Parallel()

    fakeStore := &fakeRegistryStore{}
    handler := registry.NewValidationHandler(fakeStore, map[string]registry.Checker{})

    payload := []byte(`{
        "item_id": "00000000-0000-0000-0000-000000000001",
        "org_id": "00000000-0000-0000-0000-000000000002",
        "watchlist_id": "00000000-0000-0000-0000-000000000003",
        "ecosystem": "hex",
        "package_name": "phoenix",
        "namespace": ""
    }`)

    err := handler.Handle(context.Background(), payload)
    if err != nil {
        t.Fatalf("Handle: %v", err)
    }

    if fakeStore.lastStatus != "unknown_registry" {
        t.Errorf("expected unknown_registry, got %s", fakeStore.lastStatus)
    }
}
```

Use a `fakeRegistryStore` that implements the store interface needed by the handler and records the last status written.

**Step 2: Implement the handler**

The handler struct holds a reference to the store and checker map. Its `Handle` method:
- Unmarshals the JSON payload into a struct
- Looks up the checker for the ecosystem
- If no checker exists, writes `unknown_registry` status and returns nil
- Calls `Check`; on transient error, returns the error (worker will retry via backoff)
- On success, writes the status via `UpdateWatchlistItemRegistryStatus`

The handler's `Handle` method matches the `worker.Handler` signature: `func(ctx context.Context, payload json.RawMessage) error`.

**Step 3: Run tests, verify pass, commit**

```bash
git add internal/registry/handler.go internal/registry/handler_test.go
git commit -m "feat: add registry validation worker handler"
```

---

### Task 7: Enqueue Validation Job on Item Creation

Modify `createWatchlistItemHandler` to enqueue a `registry_validate` job after successfully creating a package item. CPE items are skipped (their `registry_status` defaults to `skipped` at the DB level).

**Files:**
- Modify: `internal/api/watchlists.go` (createWatchlistItemHandler)
- Modify: `internal/api/watchlists_test.go` (verify job is enqueued)

**Step 1: Write failing test**

Add a test that creates a package item via the API and verifies a `registry_validate` job was enqueued in the job queue. Use the existing test DB infrastructure to query the `job_queue` table for a row with `queue = 'registry_validate'`.

**Step 2: Implement**

After the successful `CreateWatchlistItem` call in `createWatchlistItemHandler` and before writing the response, add:

```go
if req.ItemType == "package" {
    jobPayload, _ := json.Marshal(map[string]string{
        "item_id":      item.ID.String(),
        "org_id":       orgID.String(),
        "watchlist_id": watchlistID.String(),
        "ecosystem":    *p.Ecosystem,
        "package_name": *p.PackageName,
        "namespace":    stringOrEmpty(p.Namespace),
    })
    // Fire-and-forget: enqueue validation job. Failure to enqueue is non-fatal --
    // the item is still created, it just won't get validated.
    if _, err := srv.store.EnqueueJob(
        context.WithoutCancel(r.Context()),
        "registry_validate", 0, jobPayload, nil, 3, nil,
    ); err != nil {
        slog.WarnContext(r.Context(), "enqueue registry validation", "error", err, "item_id", item.ID)
    }
}
```

Key points:
- Uses `context.WithoutCancel` so the enqueue survives response completion
- Priority 0 (lowest -- background housekeeping)
- Max 3 attempts with worker retry
- Non-fatal: log warning on enqueue failure, never fail the item creation

Add a `stringOrEmpty` helper:
```go
func stringOrEmpty(s *string) string {
    if s == nil {
        return ""
    }
    return *s
}
```

**Step 3: Run tests, commit**

```bash
git add internal/api/watchlists.go internal/api/watchlists_test.go
git commit -m "feat: enqueue registry validation job on package item creation"
```

---

### Task 8: Register Worker Handler in Pool Setup

Wire the `registry_validate` handler into the worker pool registration in the server startup code.

**Files:**
- Modify: wherever the worker pool is initialized (search for existing `pool.Register(` calls -- likely in `cmd/cvert-ops/` or `internal/api/`)

**Step 1: Find and modify the pool setup code**

Search for existing `pool.Register(` calls and add alongside them:

```go
registryResolver := registry.NewResolver(&http.Client{Timeout: 10 * time.Second})
validationHandler := registry.NewValidationHandler(appStore, registryResolver.Checkers())
pool.Register("registry_validate", validationHandler.Handle)
```

**Step 2: Run full test suite**

Run: `go test ./... -count=1`
Expected: All pass.

**Step 3: Commit**

```bash
git add cmd/cvert-ops/
git commit -m "feat: register registry_validate worker handler"
```

---

### Task 9: API Response -- Surface `registry_status`

Update the API response types and mapping functions to include `registry_status` in watchlist item responses.

**Files:**
- Modify: `internal/api/watchlists.go` (watchlistItemEntry struct, watchlistItemToEntry function)
- Modify: `internal/api/watchlists_test.go` (verify field appears in response JSON)

**Step 1: Write failing test**

Add a test that creates a package item via the API and verifies the response JSON contains `"registry_status": "pending"`.

**Step 2: Implement**

Add field to `watchlistItemEntry`:
```go
type watchlistItemEntry struct {
    ID             string  `json:"id"`
    ItemType       string  `json:"item_type"`
    Ecosystem      *string `json:"ecosystem,omitempty"`
    PackageName    *string `json:"package_name,omitempty"`
    Namespace      *string `json:"namespace,omitempty"`
    CpeNormalized  *string `json:"cpe_normalized,omitempty"`
    RegistryStatus string  `json:"registry_status"`
    CreatedAt      string  `json:"created_at"`
}
```

Update `watchlistItemToEntry`:
```go
func watchlistItemToEntry(item store.WatchlistItemRow) watchlistItemEntry {
    e := watchlistItemEntry{
        ID:             item.ID.String(),
        ItemType:       string(item.ItemType),
        RegistryStatus: string(item.RegistryStatus),
        CreatedAt:      item.CreatedAt.Format(time.RFC3339),
    }
    // ... existing field mappings unchanged ...
    return e
}
```

**Step 3: Run tests, commit**

```bash
git add internal/api/watchlists.go internal/api/watchlists_test.go
git commit -m "feat: surface registry_status in watchlist item API responses"
```

---

### Task 10: Frontend -- Warning Badge on Watchlist Items

Add a visual badge to the watchlist detail view that shows registry validation status. Verified items show a green checkmark, unverified items show a yellow warning, pending items show a spinner.

**Files:**
- Modify: `web/src/views/WatchlistDetailView.vue`
- Modify: `web/src/components/watchlist/AddItemDialog.vue` (update WatchlistItemEntry type)

**Step 1: Update the TypeScript type**

In the file that defines `WatchlistItemEntry` (check `AddItemDialog.vue` exports), add `registry_status`:

```typescript
export interface WatchlistItemEntry {
  id: string
  item_type: 'package' | 'cpe'
  ecosystem?: string
  package_name?: string
  namespace?: string
  cpe_normalized?: string
  registry_status: 'pending' | 'verified' | 'unverified' | 'unknown_registry' | 'skipped'
  created_at: string
}
```

**Step 2: Add badge column to the items table**

In `WatchlistDetailView.vue`, add a "Registry" column to the items table between "Identifier" and "Added":

In the `<TableHeader>`:
```vue
<TableHead class="w-28">Registry</TableHead>
```

In each `<TableRow>`:
```vue
<TableCell>
  <Badge
    v-if="item.item_type === 'package'"
    :variant="registryBadgeVariant(item.registry_status)"
    :data-testid="`registry-status-${item.id}`"
  >
    <Loader2
      v-if="item.registry_status === 'pending'"
      class="mr-1 size-3 animate-spin"
      aria-hidden="true"
    />
    <CheckCircle2
      v-else-if="item.registry_status === 'verified'"
      class="mr-1 size-3"
      aria-hidden="true"
    />
    <AlertTriangle
      v-else-if="item.registry_status === 'unverified'"
      class="mr-1 size-3"
      aria-hidden="true"
    />
    {{ registryStatusLabel(item.registry_status) }}
  </Badge>
  <span v-else class="text-muted-foreground text-xs">N/A</span>
</TableCell>
```

**Step 3: Add helper functions**

```typescript
function registryBadgeVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
  switch (status) {
    case 'verified': return 'default'
    case 'unverified': return 'destructive'
    case 'pending': return 'outline'
    default: return 'secondary'
  }
}

function registryStatusLabel(status: string): string {
  switch (status) {
    case 'verified': return 'Verified'
    case 'unverified': return 'Not found'
    case 'pending': return 'Checking...'
    case 'unknown_registry': return 'No registry'
    case 'skipped': return 'Skipped'
    default: return status
  }
}
```

**Step 4: Add imports for icons**

Add `CheckCircle2` and `AlertTriangle` to the lucide-vue-next imports.

**Step 5: Run frontend tests and build**

Run: `cd web && npm run type-check && npm run build`
Expected: No type errors, build succeeds.

Run: `cd web && npm test`
Expected: Existing tests pass. Update test snapshots if needed.

**Step 6: Commit**

```bash
git add web/src/
git commit -m "feat: add registry status badge to watchlist item UI"
```

---

### Task 11: Frontend Tests for Registry Badge

Add component tests verifying the registry status badge renders correctly for each status.

**Files:**
- Modify: `web/src/views/__tests__/WatchlistDetailView.test.ts`

**Step 1: Write tests**

Add test cases that mock API responses with different `registry_status` values and verify:
- `verified` items show a badge with "Verified" text
- `unverified` items show a destructive badge with "Not found" text
- `pending` items show a badge with "Checking..." text
- CPE items show "N/A" (no registry badge)

**Step 2: Run tests, verify pass**

Run: `cd web && npm test`
Expected: All pass.

**Step 3: Commit**

```bash
git add web/src/views/__tests__/
git commit -m "test: add registry status badge rendering tests"
```

---

### Task 12: Store-Level Integration Tests

Add integration tests that verify the full flow: create item -> item has `pending` status -> update status -> verify updated status is returned in list queries.

**Files:**
- Modify: `internal/store/watchlist_test.go`

**Step 1: Write tests**

```go
func TestCreateWatchlistItem_DefaultRegistryStatus(t *testing.T) {
    // Create a package item, verify registry_status is 'pending'
}

func TestCreateWatchlistItem_CPE_DefaultRegistryStatus(t *testing.T) {
    // Create a CPE item, verify registry_status is 'skipped'
}

func TestUpdateWatchlistItemRegistryStatus(t *testing.T) {
    // Create item, update status to 'verified', re-fetch, verify
}

func TestListPendingRegistryItems(t *testing.T) {
    // Create multiple items across orgs with different statuses,
    // verify only pending package items returned, ordered by created_at ASC
}
```

**Step 2: Run tests, verify pass**

Run: `go test ./internal/store/ -run TestCreate.*RegistryStatus -v`
Run: `go test ./internal/store/ -run TestUpdate.*RegistryStatus -v`
Run: `go test ./internal/store/ -run TestListPending -v`
Expected: All PASS

**Step 3: Commit**

```bash
git add internal/store/watchlist_test.go
git commit -m "test: add registry_status integration tests for watchlist items"
```

---

## Future Work (Not in This Plan)

These items are documented for context but should NOT be implemented as part of this feature:

1. **Go proxy checker:** `proxy.golang.org` returns 404 for modules that have never been fetched through the proxy, making it unreliable for validation. Defer until a better approach is found (e.g., checking `pkg.go.dev` API).

2. **Maven Central checker:** Requires parsing the two-part `groupId:artifactId` coordinate and querying the Solr search API. More complex than the simple HEAD/GET checkers.

3. **NuGet checker:** V3 registration endpoint is straightforward but lower priority due to lower CVE volume in the .NET ecosystem.

4. **Periodic re-validation:** A cron job that re-checks `unverified` items periodically (packages may be published after the watchlist entry was created). Could use a `registry_checked_at` timestamp column.

5. **Private package skip heuristics:** Auto-detect private scopes (e.g., npm `@company/` where company is not a known public org) and set `skipped` status.

6. **Bulk validation on import:** When users import watchlists from SBOMs, batch-validate all items instead of one job per item.

---

## Dependency Graph

```
Task 1 (migration)
  └── Task 2 (sqlc regen + store)
        ├── Task 3 (npm checker)
        │     └── Task 4 (pypi, crates, rubygems checkers)
        │           └── Task 5 (resolver)
        │                 └── Task 6 (worker handler)
        │                       └── Task 8 (wire into pool)
        ├── Task 7 (enqueue on create -- needs store from T2)
        ├── Task 9 (API response -- needs store from T2)
        │     └── Task 10 (frontend badge -- needs API from T9)
        │           └── Task 11 (frontend tests)
        └── Task 12 (store integration tests)
```

Tasks 3-6 and Tasks 9-11 can proceed in parallel after Task 2 is complete.
