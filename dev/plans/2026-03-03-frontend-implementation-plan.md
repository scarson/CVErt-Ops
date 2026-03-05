# Frontend Implementation Plan: CVErt Ops Web Application

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Vue 3 SPA frontend for CVErt Ops, embedded in the Go binary via `embed.FS`, covering the core workflow: auth, CVE search/detail, watchlists, member/group management, and feed status.

**Architecture:** Vue 3 + TypeScript SPA served by the Go binary. Vite builds static assets into `web/dist/`, Go embeds them via `//go:embed all:dist`. In development, Vite dev server proxies `/api` to the Go backend. API client auto-generated from the OpenAPI spec with typed fetch wrapper, CSRF header middleware, and 401 refresh interceptor.

**Tech Stack:** Vue 3, TypeScript, Vite, Tailwind CSS v4, shadcn-vue (reka-ui), Pinia, Vue Router 4, openapi-typescript, openapi-fetch, Vitest, ESLint, Prettier

**Design doc:** `dev/plans/2026-03-03-frontend-design.md`

**Module path:** `github.com/scarson/cvert-ops`

---

## Before Starting

Read these files to understand the existing codebase:
- `internal/api/server.go` — route registration (huma + chi), middleware chain, `Handler()` method
- `internal/config/config.go` — caarlos0/env config struct pattern
- `cmd/cvert-ops/main.go` — cobra command structure, startup sequence
- `internal/api/middleware_csrf.go` — CSRF `X-Requested-By` header requirement
- `internal/api/middleware_auth.go` — cookie + Bearer auth extraction
- `internal/api/context.go` — context key definitions (ctxUserID, ctxOrgID, etc.)
- `dev/plans/2026-03-03-frontend-design.md` — full design doc with all decisions

**Key conventions:**
- Every `.go` file starts with a 2-line `// ABOUTME:` comment
- Every `.vue`, `.ts` file starts with a 2-line `// ABOUTME:` comment
- TDD: write failing test → verify failure → implement → verify pass → commit
- Use `/frontend-design` skill when building page-level components for distinctive UI
- OpenAPI spec is served at `/api/v1/openapi.json` by huma automatically

---

## Phase A: Project Foundation

### Task 1: Scaffold Vue 3 project ✅ `dd99764`

**Files:**
- Create: `web/` directory (entire scaffolded project)

**Step 1:** From the repo root, scaffold the Vue project:

```bash
npm create vue@latest web -- --typescript --router --pinia --vitest --eslint-with-prettier
```

If the interactive CLI doesn't support `--` flags, run interactively and select:
- TypeScript: Yes
- JSX: No
- Vue Router: Yes
- Pinia: Yes
- Vitest: Yes
- E2E testing: No
- ESLint + Prettier: Yes

**Step 2:** Install dependencies:

```bash
cd web && npm install
```

**Step 3:** Remove nested `.git` if created (we're in an existing repo):

```bash
rm -rf web/.git
```

**Step 4:** Verify the dev server starts:

```bash
cd web && npm run dev
```

Expected: Vite dev server starts on port 5173. Stop it after verifying.

**Step 5:** Add `.node-version` at repo root:

```
20
```

**Step 6:** Commit:

```bash
git add web/ .node-version
git commit -m "feat(web): scaffold Vue 3 + TypeScript project"
```

---

### Task 2: Add Tailwind CSS v4 ✅ `85a3923`

**Files:**
- Modify: `web/vite.config.ts`
- Modify: `web/src/assets/main.css` (or create `web/src/style.css`)

**Step 1:** Install Tailwind v4 and the Vite plugin:

```bash
cd web && npm install tailwindcss @tailwindcss/vite
```

**Step 2:** Update `web/vite.config.ts` to include the Tailwind plugin and `@` path alias:

```typescript
// ABOUTME: Vite configuration for the CVErt Ops frontend.
// ABOUTME: Includes Tailwind CSS v4, Vue, path aliases, and API proxy.

import path from 'node:path'
import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
```

**Step 3:** Install `@types/node` for the path import:

```bash
cd web && npm install -D @types/node
```

**Step 4:** Replace the contents of the main CSS file (`web/src/assets/main.css` or equivalent) with:

```css
@import "tailwindcss";
```

Remove any default Vue scaffold CSS.

**Step 5:** Verify Tailwind works. Update `web/src/App.vue` temporarily:

```vue
<template>
  <div class="bg-blue-500 text-white p-4">Tailwind works</div>
</template>
```

Run `cd web && npm run dev`, verify the blue box renders. Revert `App.vue` after.

**Step 6:** Commit:

```bash
git add web/
git commit -m "feat(web): add Tailwind CSS v4"
```

---

### Task 3: Initialize shadcn-vue ✅ `d402974`

**Files:**
- Create: `web/components.json`
- Create: `web/src/lib/utils.ts`
- Modify: `web/src/assets/main.css` (adds theme CSS variables)

**Step 1:** Initialize shadcn-vue:

```bash
cd web && npx shadcn-vue@latest init
```

When prompted:
- Style: New York
- Base color: Neutral (or Zinc — choose a neutral palette)
- CSS file: `src/assets/main.css`

This creates `components.json`, adds CSS custom properties to the main CSS file, installs `clsx`, `tailwind-merge`, `class-variance-authority`, and `reka-ui`.

**Step 2:** Verify `web/src/lib/utils.ts` was created with the `cn()` utility:

```typescript
import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
```

**Step 3:** Verify TypeScript path aliases are set up in `web/tsconfig.app.json`:

```json
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"]
    }
  }
}
```

Add if missing.

**Step 4:** Add initial shadcn-vue components needed for auth pages:

```bash
cd web && npx shadcn-vue@latest add button input label card sonner
```

**Step 5:** Verify a component renders. Create a temporary test in `App.vue`:

```vue
<script setup lang="ts">
import { Button } from '@/components/ui/button'
</script>

<template>
  <div class="p-8">
    <Button>Test Button</Button>
  </div>
</template>
```

Run `npm run dev`, verify the button renders with styling. Revert after.

**Step 6:** Commit:

```bash
git add web/
git commit -m "feat(web): initialize shadcn-vue with base components"
```

---

### Task 4: Install API client tooling ✅ `e136e1b`

**Files:**
- Modify: `web/package.json` (new dependencies + script)

**Step 1:** Install openapi-typescript and openapi-fetch:

```bash
cd web && npm install openapi-fetch && npm install -D openapi-typescript
```

**Step 2:** Add the `generate-api` script to `web/package.json`:

```json
{
  "scripts": {
    "generate-api": "openapi-typescript ../openapi.json -o src/lib/api/schema.d.ts"
  }
}
```

Note: The OpenAPI spec will be fetched from the running Go server and saved to `openapi.json` at the repo root. The npm script generates types from that file.

**Step 3:** Commit:

```bash
git add web/package.json web/package-lock.json
git commit -m "feat(web): add openapi-typescript + openapi-fetch"
```

---

### Task 5: Configure Vitest for Vue ✅ `3691fba`

> **Deviation:** Swapped jsdom for happy-dom (faster, lighter). Added `happy-dom` to devDependencies, removed `jsdom`. Updated `tsconfig.vitest.json` types accordingly. Extra commit `1d01817` for tsconfig fix.

**Files:**
- Modify: `web/vite.config.ts` (add test config)
- Modify: `web/tsconfig.app.json` (add vitest globals type)

**Step 1:** Install `happy-dom` for the test environment:

```bash
cd web && npm install -D happy-dom @vue/test-utils
```

Note: `@vue/test-utils` may already be installed by `create-vue`. Install if missing.

**Step 2:** Add the `test` configuration to `web/vite.config.ts`:

```typescript
/// <reference types="vitest/config" />
// ABOUTME: Vite configuration for the CVErt Ops frontend.
// ABOUTME: Includes Tailwind CSS v4, Vue, path aliases, API proxy, and Vitest.

import path from 'node:path'
import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  test: {
    globals: true,
    environment: 'happy-dom',
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    exclude: ['node_modules', 'dist'],
  },
})
```

**Step 3:** Add Vitest globals type to `web/tsconfig.app.json`:

```json
{
  "compilerOptions": {
    "types": ["vitest/globals"]
  }
}
```

**Step 4:** Write a smoke test to verify the setup. Create `web/src/components/__tests__/smoke.test.ts`:

```typescript
// ABOUTME: Smoke test to verify Vitest + Vue Test Utils setup.
// ABOUTME: Remove this once real component tests exist.

import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent } from 'vue'

const TestComponent = defineComponent({
  template: '<div>hello</div>',
})

describe('vitest setup', () => {
  it('mounts a Vue component', () => {
    const wrapper = mount(TestComponent)
    expect(wrapper.text()).toBe('hello')
  })
})
```

**Step 5:** Run the test:

```bash
cd web && npm run test -- --run
```

Expected: 1 test passes.

**Step 6:** Commit:

```bash
git add web/
git commit -m "feat(web): configure Vitest with happy-dom"
```

---

### Task 6: Create web/embed.go ✅ `183267c`

**Files:**
- Create: `web/embed.go`
- Create: `web/dist/.gitkeep` (temporary — allows `go build` before frontend build)

**Step 1:** Create `web/embed.go`:

```go
// ABOUTME: Embeds the frontend static assets (built by Vite) into the Go binary.
// ABOUTME: Import this package and use web.Assets to serve the SPA.

package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var assets embed.FS

// Assets returns the frontend static files rooted at the dist/ directory.
// The returned FS has the dist/ prefix stripped, so files are accessed
// as "index.html" rather than "dist/index.html".
func Assets() (fs.FS, error) {
	return fs.Sub(assets, "dist")
}
```

Note: We use a function instead of a bare variable because `fs.Sub` can return an error, and we want to strip the `dist/` prefix so the SPA handler doesn't need to know about the embed structure.

**Step 2:** Create a minimal `web/dist/.gitkeep` so the `dist/` directory exists for `go build`:

```bash
mkdir -p web/dist && touch web/dist/.gitkeep
```

**Step 3:** Add to `web/.gitignore` (the one created by create-vue) — ensure `dist/` contents are ignored except `.gitkeep`:

Verify `web/.gitignore` contains:

```
node_modules
dist
*.local
```

Then create a `web/dist/.gitignore` to force-include the directory:

```
# Ignore everything in dist except this file
*
!.gitkeep
!.gitignore
```

Wait — this approach is tricky. Simpler: just track `web/dist/.gitkeep` with `git add -f web/dist/.gitkeep`.

**Step 4:** Verify Go can compile the package:

```bash
go build ./web/...
```

Expected: builds cleanly.

**Step 5:** Commit:

```bash
git add web/embed.go
git add -f web/dist/.gitkeep web/dist/.gitignore
git commit -m "feat(web): add embed.go for SPA static assets"
```

---

### Task 7: Add FRONTEND_URL config ✅ `458d970`

**Files:**
- Modify: `internal/config/config.go`
- Modify: `.env.example`

**Step 1:** Read `internal/config/config.go` to find the Server section.

**Step 2:** Add `FrontendURL` after `ExternalURL`:

```go
FrontendURL string `env:"FRONTEND_URL" envDefault:"/"`
```

In production, `FRONTEND_URL` defaults to `/` (same-origin). In development, set to `http://localhost:5173` to redirect to Vite.

**Step 3:** Add to the `LogValue()` method's `slog.GroupValue()`:

```go
slog.String("frontend_url", c.FrontendURL),
```

**Step 4:** Update `.env.example` with a comment:

```
# FRONTEND_URL is where the browser frontend runs. Defaults to "/" (same-origin,
# for production where Go serves the SPA). Set to http://localhost:5173 for
# development with Vite dev server. Used for post-OAuth redirect.
# FRONTEND_URL=/
```

**Step 5:** Build to verify:

```bash
go build ./...
```

**Step 6:** Commit:

```bash
git add internal/config/config.go .env.example
git commit -m "feat(config): add FRONTEND_URL for post-OAuth redirect"
```

---

### Task 8: Add SPA fallback handler ✅ `3402730`

**Files:**
- Create: `internal/api/spa.go`
- Create: `internal/api/spa_test.go`
- Modify: `internal/api/server.go` (register SPA handler)

**Step 1:** Write the test. Create `internal/api/spa_test.go`:

```go
// ABOUTME: Tests for the SPA fallback handler that serves the embedded frontend.
// ABOUTME: Verifies static files are served, unknown paths return index.html, and /api is not caught.

package api

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPAHandler_ServesStaticFile(t *testing.T) {
	t.Parallel()
	staticFS := fstest.MapFS{
		"index.html":          {Data: []byte("<html>app</html>")},
		"assets/index-abc.js": {Data: []byte("console.log('app')")},
	}
	handler := newSPAHandler(staticFS)

	req := httptest.NewRequest(http.MethodGet, "/assets/index-abc.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	assert.Equal(t, "console.log('app')", string(body))
}

func TestSPAHandler_FallsBackToIndexHTML(t *testing.T) {
	t.Parallel()
	staticFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>app</html>")},
	}
	handler := newSPAHandler(staticFS)

	req := httptest.NewRequest(http.MethodGet, "/cves/CVE-2024-1234", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	assert.Equal(t, "<html>app</html>", string(body))
}

func TestSPAHandler_CacheHeaders_HashedAsset(t *testing.T) {
	t.Parallel()
	staticFS := fstest.MapFS{
		"index.html":          {Data: []byte("<html>app</html>")},
		"assets/index-abc.js": {Data: []byte("js")},
	}
	handler := newSPAHandler(staticFS)

	req := httptest.NewRequest(http.MethodGet, "/assets/index-abc.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Contains(t, rec.Header().Get("Cache-Control"), "max-age=31536000")
	assert.Contains(t, rec.Header().Get("Cache-Control"), "immutable")
}

func TestSPAHandler_CacheHeaders_IndexHTML(t *testing.T) {
	t.Parallel()
	staticFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>app</html>")},
	}
	handler := newSPAHandler(staticFS)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
}
```

**Step 2:** Run test to verify it fails:

```bash
go test ./internal/api/ -run TestSPAHandler -v
```

Expected: FAIL — `newSPAHandler` not defined.

**Step 3:** Implement the SPA handler. Create `internal/api/spa.go`:

```go
// ABOUTME: SPA fallback handler for serving the embedded Vue frontend.
// ABOUTME: Serves static files from the embedded FS; unknown paths return index.html.

package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// newSPAHandler returns an http.Handler that serves static files from the
// provided filesystem. If the requested path does not exist, it serves
// index.html (SPA client-side routing fallback).
//
// Cache policy:
//   - Files under assets/ get immutable caching (Vite hashes filenames)
//   - index.html gets no-cache (must always be fresh)
func newSPAHandler(staticFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(staticFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clean the path and try to open the file.
		p := path.Clean(r.URL.Path)
		if p == "/" {
			p = "index.html"
		} else {
			p = strings.TrimPrefix(p, "/")
		}

		// Check if the file exists in the embedded FS.
		f, err := staticFS.Open(p)
		if err != nil {
			// File doesn't exist — serve index.html (SPA fallback).
			setCacheHeaders(w, "index.html")
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}
		f.Close()

		// File exists — serve it with appropriate cache headers.
		setCacheHeaders(w, p)
		fileServer.ServeHTTP(w, r)
	})
}

func setCacheHeaders(w http.ResponseWriter, filePath string) {
	if strings.HasPrefix(filePath, "assets/") {
		// Vite-hashed assets — cache forever.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		// index.html and other non-hashed files — always revalidate.
		w.Header().Set("Cache-Control", "no-cache")
	}
}
```

**Step 4:** Run test to verify it passes:

```bash
go test ./internal/api/ -run TestSPAHandler -v
```

Expected: all 4 tests PASS.

**Step 5:** Register the SPA handler in `server.go`. Read `internal/api/server.go` and find the `Handler()` method. After the `r.Mount("/api/v1", apiRouter)` line, add:

```go
// ── SPA fallback (serves embedded frontend) ─────────────────────────────
if frontendFS, err := web.Assets(); err == nil {
	r.Handle("/*", newSPAHandler(frontendFS))
}
```

Add the import:

```go
"github.com/scarson/cvert-ops/web"
```

**Step 6:** Run all tests to verify nothing broke:

```bash
go test ./internal/api/... -v -count=1
```

**Step 7:** Commit:

```bash
git add internal/api/spa.go internal/api/spa_test.go internal/api/server.go
git commit -m "feat(api): add SPA fallback handler for embedded frontend"
```

---

### Task 9: OAuth callback redirect ✅ `d681984`

**Files:**
- Modify: `internal/api/auth.go` (GitHub + Google callback handlers)
- Modify: `internal/api/auth_test.go` (update tests)

**Step 1:** Read `internal/api/auth.go` and find the GitHub callback handler (`githubCallbackHandler` or similar). Locate where it returns the JSON response (something like `writeJSON(w, http.StatusOK, map[string]string{"user_id": userID.String()})`).

**Step 2:** Replace the JSON response with a redirect:

```go
http.Redirect(w, r, srv.cfg.FrontendURL, http.StatusFound)
```

**Step 3:** Do the same for the Google OIDC callback handler.

**Step 4:** Update the corresponding tests. The tests currently check for a JSON body — update them to check for a 302 redirect with `Location` header equal to `cfg.FrontendURL`.

```go
assert.Equal(t, http.StatusFound, rec.Code)
assert.Equal(t, srv.cfg.FrontendURL, rec.Header().Get("Location"))
```

**Step 5:** Run the auth tests:

```bash
go test ./internal/api/ -run TestGitHub -v
go test ./internal/api/ -run TestGoogle -v
```

Expected: all tests pass.

**Step 6:** Commit:

```bash
git add internal/api/auth.go internal/api/auth_test.go
git commit -m "feat(auth): OAuth callbacks redirect to FRONTEND_URL instead of returning JSON"
```

---

### Task 10: Verify end-to-end dev workflow ⏳ DEFERRED

> **Deferred:** Requires running Go server + Postgres + Vite dev server simultaneously. Will verify manually once all frontend code is in place.

**Not a code task — manual verification.**

**Step 1:** Start the Go server:

```bash
go run ./cmd/cvert-ops serve
```

**Step 2:** In another terminal, start the Vite dev server:

```bash
cd web && npm run dev
```

**Step 3:** Open `http://localhost:5173` in a browser. Verify:
- Vite serves the Vue app
- No console errors

**Step 4:** Open `http://localhost:5173/api/v1/healthz` (or any API endpoint). Verify:
- The proxy forwards to the Go server
- You get a JSON response (not the Vue app)

**Step 5:** Build the production bundle and verify embedding:

```bash
cd web && npm run build
cd .. && go build ./cmd/cvert-ops
./cvert-ops serve  # or go run ./cmd/cvert-ops serve
```

Open `http://localhost:8080`. Verify the Vue app is served from the Go binary.

**Step 6:** Commit any fixes found. If everything works, no commit needed.

---

## Phase B: API Client + Auth Infrastructure

### Task 11: Generate API types from OpenAPI spec ✅ `2d0e20b`, `f34050d`

> **Deviation:** Instead of curling the spec from a running server, created `internal/api/openapi_test.go` (`TestOpenAPISpec`) that generates the spec from huma route registrations without a database. Run `GENERATE_OPENAPI=1 go test -run TestOpenAPISpec ./internal/api/` to regenerate. `openapi.json` is committed (not gitignored) to document the API contract.

**Files:**
- Create: `web/src/lib/api/schema.d.ts` (generated)
- Create: `openapi.json` (at repo root, gitignored)

**Step 1:** Ensure the Go server is running. Fetch the OpenAPI spec:

```bash
curl -s http://localhost:8080/api/v1/openapi.json > openapi.json
```

**Step 2:** Add `openapi.json` to the root `.gitignore` (it's a fetched artifact):

```
openapi.json
```

**Step 3:** Create the output directory:

```bash
mkdir -p web/src/lib/api
```

**Step 4:** Generate TypeScript types:

```bash
cd web && npm run generate-api
```

This runs `openapi-typescript ../openapi.json -o src/lib/api/schema.d.ts`.

**Step 5:** Verify the generated file exists and contains type definitions:

```bash
head -20 web/src/lib/api/schema.d.ts
```

Expected: TypeScript interface definitions for `paths`, `components`, etc.

**Step 6:** Commit the generated types:

```bash
git add web/src/lib/api/schema.d.ts .gitignore
git commit -m "feat(web): generate TypeScript API types from OpenAPI spec"
```

---

### Task 12: Create API client with CSRF + refresh interceptor ✅ `aea2ecf`

> **Note:** Tests expanded from 3 (plan) to 12 — added coverage for PUT, DELETE, HEAD, OPTIONS methods and refresh middleware behavior (non-401 passthrough, login/refresh endpoint exclusion, retry on success, redirect on failure).

**Files:**
- Create: `web/src/lib/api/client.ts`
- Create: `web/src/lib/api/__tests__/client.test.ts`

**Step 1:** Write the test. Create `web/src/lib/api/__tests__/client.test.ts`:

```typescript
// ABOUTME: Tests for the API client configuration.
// ABOUTME: Verifies CSRF header injection and 401 refresh interceptor behavior.

import { describe, it, expect, vi, beforeEach } from 'vitest'

// We'll test the middleware functions in isolation rather than
// making real HTTP calls. The client module exports its middleware
// for testability.

describe('CSRF middleware', () => {
  it('adds X-Requested-By header to POST requests', async () => {
    const { csrfMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/test', {
      method: 'POST',
    })
    const result = await csrfMiddleware.onRequest({ request, schemaPath: '/test', params: {} })
    expect(result.headers.get('X-Requested-By')).toBe('CVErt-Ops')
  })

  it('adds X-Requested-By header to PATCH requests', async () => {
    const { csrfMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/test', {
      method: 'PATCH',
    })
    const result = await csrfMiddleware.onRequest({ request, schemaPath: '/test', params: {} })
    expect(result.headers.get('X-Requested-By')).toBe('CVErt-Ops')
  })

  it('does not add X-Requested-By header to GET requests', async () => {
    const { csrfMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/test', {
      method: 'GET',
    })
    const result = await csrfMiddleware.onRequest({ request, schemaPath: '/test', params: {} })
    expect(result.headers.get('X-Requested-By')).toBeNull()
  })
})
```

**Step 2:** Run test to verify it fails:

```bash
cd web && npm run test -- --run src/lib/api/__tests__/client.test.ts
```

Expected: FAIL — module not found.

**Step 3:** Implement the API client. Create `web/src/lib/api/client.ts`:

```typescript
// ABOUTME: Typed API client for the CVErt Ops backend.
// ABOUTME: Auto-configured with CSRF header and 401 refresh interceptor.

import createClient, { type Middleware } from 'openapi-fetch'
import type { paths } from './schema'

// CSRF middleware: adds X-Requested-By header to state-changing requests.
// Required by the backend's csrfProtect middleware for cookie-authenticated requests.
export const csrfMiddleware: Middleware = {
  async onRequest({ request }) {
    const method = request.method.toUpperCase()
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      request.headers.set('X-Requested-By', 'CVErt-Ops')
    }
    return request
  },
}

// Refresh lock: prevents multiple concurrent refresh calls when several
// API requests get 401 simultaneously.
let refreshPromise: Promise<boolean> | null = null

async function refreshTokens(): Promise<boolean> {
  try {
    const res = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-Requested-By': 'CVErt-Ops' },
    })
    return res.ok
  } catch {
    return false
  }
}

// 401 refresh interceptor: attempts token refresh on auth failure,
// then retries the original request.
export const refreshMiddleware: Middleware = {
  async onResponse({ request, response }) {
    if (response.status !== 401) {
      return response
    }

    // Don't try to refresh the refresh endpoint itself.
    if (request.url.includes('/auth/refresh') || request.url.includes('/auth/login')) {
      return response
    }

    // Use existing refresh if one is in progress (prevents concurrent refreshes).
    if (!refreshPromise) {
      refreshPromise = refreshTokens()
    }

    const success = await refreshPromise
    refreshPromise = null

    if (!success) {
      // Refresh failed — redirect to login.
      window.location.href = '/login'
      return response
    }

    // Retry the original request with fresh cookies.
    return fetch(request, { credentials: 'include' })
  },
}

const client = createClient<paths>({
  baseUrl: '/api/v1',
  credentials: 'include',
})

client.use(csrfMiddleware)
client.use(refreshMiddleware)

export default client
```

**Step 4:** Run test to verify it passes:

```bash
cd web && npm run test -- --run src/lib/api/__tests__/client.test.ts
```

Expected: all tests PASS.

**Step 5:** Commit:

```bash
git add web/src/lib/api/client.ts web/src/lib/api/__tests__/client.test.ts
git commit -m "feat(web): API client with CSRF header and 401 refresh interceptor"
```

---

### Task 13: Create auth Pinia store ✅ `53fa732`

> **Note:** Used generated OpenAPI schema types (`MeOutputBody`, `OrgEntry`) instead of defining duplicate `User`/`UserOrg` interfaces. Tests expanded from 4 (plan) to 17 — added coverage for `activeOrg` computed, `fetchMe` edge cases (auto-select single org, stale org cleanup), login/logout flows.

**Files:**
- Create: `web/src/stores/auth.ts`
- Create: `web/src/stores/__tests__/auth.test.ts`

**Step 1:** Write the test. Create `web/src/stores/__tests__/auth.test.ts`:

```typescript
// ABOUTME: Tests for the auth Pinia store.
// ABOUTME: Verifies login, logout, org selection, and session persistence.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAuthStore } from '../auth'

// Mock the API client
vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn(),
    POST: vi.fn(),
  },
}))

describe('auth store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
  })

  it('starts with no user and not authenticated', () => {
    const auth = useAuthStore()
    expect(auth.isAuthenticated).toBe(false)
    expect(auth.user).toBeNull()
    expect(auth.activeOrgId).toBeNull()
  })

  it('sets activeOrgId and persists to localStorage', () => {
    const auth = useAuthStore()
    const orgId = '550e8400-e29b-41d4-a716-446655440001'
    auth.setActiveOrg(orgId)
    expect(auth.activeOrgId).toBe(orgId)
    expect(localStorage.getItem('activeOrgId')).toBe(orgId)
  })

  it('loads activeOrgId from localStorage on init', () => {
    const orgId = '550e8400-e29b-41d4-a716-446655440001'
    localStorage.setItem('activeOrgId', orgId)
    const auth = useAuthStore()
    auth.loadPersistedOrg()
    expect(auth.activeOrgId).toBe(orgId)
  })

  it('clears state on logout', () => {
    const auth = useAuthStore()
    auth.setActiveOrg('some-org-id')
    auth.clearAuth()
    expect(auth.isAuthenticated).toBe(false)
    expect(auth.user).toBeNull()
    expect(auth.activeOrgId).toBeNull()
    expect(localStorage.getItem('activeOrgId')).toBeNull()
  })
})
```

**Step 2:** Run test to verify it fails:

```bash
cd web && npm run test -- --run src/stores/__tests__/auth.test.ts
```

**Step 3:** Implement the store. Create `web/src/stores/auth.ts`:

```typescript
// ABOUTME: Auth store — manages user session, org context, and login/logout.
// ABOUTME: Active org persisted in localStorage for page-refresh survival.

import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import client from '@/lib/api/client'

export interface UserOrg {
  org_id: string
  name: string
  role: string
}

export interface User {
  user_id: string
  email: string
  display_name: string
  orgs: UserOrg[]
}

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const activeOrgId = ref<string | null>(null)

  const isAuthenticated = computed(() => user.value !== null)

  const activeOrg = computed(() => {
    if (!user.value || !activeOrgId.value) return null
    return user.value.orgs.find((o) => o.org_id === activeOrgId.value) ?? null
  })

  function setActiveOrg(orgId: string) {
    activeOrgId.value = orgId
    localStorage.setItem('activeOrgId', orgId)
  }

  function loadPersistedOrg() {
    const stored = localStorage.getItem('activeOrgId')
    if (stored) {
      activeOrgId.value = stored
    }
  }

  async function fetchMe(): Promise<boolean> {
    const { data, error } = await client.GET('/auth/me')
    if (error || !data) {
      return false
    }
    user.value = data as User
    loadPersistedOrg()

    // Validate persisted org is still in user's org list.
    if (activeOrgId.value) {
      const stillMember = user.value.orgs.some((o) => o.org_id === activeOrgId.value)
      if (!stillMember) {
        activeOrgId.value = null
        localStorage.removeItem('activeOrgId')
      }
    }

    // Auto-select if user has exactly one org.
    if (!activeOrgId.value && user.value.orgs.length === 1) {
      setActiveOrg(user.value.orgs[0].org_id)
    }

    return true
  }

  async function login(email: string, password: string): Promise<{ success: boolean; error?: string }> {
    const { error } = await client.POST('/auth/login', {
      body: { email, password },
    })
    if (error) {
      return { success: false, error: 'Invalid email or password' }
    }
    const fetched = await fetchMe()
    return { success: fetched }
  }

  async function logout() {
    await client.POST('/auth/logout')
    clearAuth()
  }

  function clearAuth() {
    user.value = null
    activeOrgId.value = null
    localStorage.removeItem('activeOrgId')
  }

  return {
    user,
    activeOrgId,
    activeOrg,
    isAuthenticated,
    setActiveOrg,
    loadPersistedOrg,
    fetchMe,
    login,
    logout,
    clearAuth,
  }
})
```

**Step 4:** Run test to verify it passes:

```bash
cd web && npm run test -- --run src/stores/__tests__/auth.test.ts
```

**Step 5:** Commit:

```bash
git add web/src/stores/auth.ts web/src/stores/__tests__/auth.test.ts
git commit -m "feat(web): auth Pinia store with org context and localStorage persistence"
```

---

### Task 14: Create UI store (toasts) ✅ `9f20ffc`

**Files:**
- Create: `web/src/stores/ui.ts`

**Step 1:** Create `web/src/stores/ui.ts`:

```typescript
// ABOUTME: UI store for cross-component state (toasts, sidebar).
// ABOUTME: Uses shadcn-vue's Sonner for toast notifications.

import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useUIStore = defineStore('ui', () => {
  const sidebarCollapsed = ref(false)

  function toggleSidebar() {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }

  return {
    sidebarCollapsed,
    toggleSidebar,
  }
})
```

Note: Toast notifications use shadcn-vue's Sonner component directly (import `toast` from `sonner`). No store needed for toasts — Sonner manages its own state. The UI store is for sidebar and other global UI state.

**Step 2:** Commit:

```bash
git add web/src/stores/ui.ts
git commit -m "feat(web): UI store for sidebar state"
```

---

## Phase C: Layout + Routing

### Task 15: Create PublicLayout ✅ `e5c06df`

**Files:**
- Create: `web/src/layouts/PublicLayout.vue`

**Step 1:** Create `web/src/layouts/PublicLayout.vue`:

```vue
<!-- ABOUTME: Layout for unauthenticated pages (login, register, invitation). -->
<!-- ABOUTME: Minimal centered layout with the app logo/name. -->

<script setup lang="ts">
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-background">
    <div class="w-full max-w-md space-y-6 px-4">
      <div class="text-center">
        <h1 class="text-2xl font-bold tracking-tight">CVErt Ops</h1>
        <p class="text-sm text-muted-foreground">Vulnerability Intelligence</p>
      </div>
      <slot />
    </div>
  </div>
</template>
```

**Step 2:** Commit:

```bash
git add web/src/layouts/PublicLayout.vue
git commit -m "feat(web): PublicLayout for unauthenticated pages"
```

---

### Task 16: Create AuthenticatedLayout (sidebar) ✅ `db783e2`

> **Note:** Added 8 component tests for sidebar nav links, org switcher, and user menu. Uses sidebar CSS variables from main.css theme. Mobile responsive via Sheet component.

**Files:**
- Create: `web/src/layouts/AuthenticatedLayout.vue`
- Create: `web/src/components/AppSidebar.vue`
- Create: `web/src/components/OrgSwitcher.vue`
- Create: `web/src/components/UserMenu.vue`

**Step 1:** Add required shadcn-vue components:

```bash
cd web && npx shadcn-vue@latest add dropdown-menu separator avatar sheet tooltip
```

**Step 2:** Use the `/frontend-design` skill to create the authenticated layout with sidebar navigation. The layout must include:

- **Sidebar** with navigation sections:
  - CVE Search (`/cves`)
  - Watchlists (`/watchlists`)
  - Settings section: Members (`/settings/members`), Groups (`/settings/groups`)
  - Admin section: Feed Status (`/admin/feeds`)
- **Org switcher** in sidebar header — shows active org, dropdown to switch
- **User menu** in sidebar footer — shows display name, logout option
- **Main content area** with `<slot />`
- **Mobile responsive** — sidebar collapses to a sheet/drawer on small screens

Each sub-component (`AppSidebar.vue`, `OrgSwitcher.vue`, `UserMenu.vue`) should be in `web/src/components/`.

**Step 3:** Write component tests for the sidebar navigation links:

```typescript
// web/src/components/__tests__/AppSidebar.test.ts
// Verify that:
// - All navigation links render
// - Active route is highlighted
// - Org switcher shows active org name
// - User menu shows display name
```

**Step 4:** Run tests, verify pass.

**Step 5:** Commit:

```bash
git add web/src/layouts/ web/src/components/
git commit -m "feat(web): AuthenticatedLayout with sidebar navigation"
```

---

### Task 17: Create Vue Router with guards ✅ `f9b31a7`

> **Note:** Extracted guard functions as named exports for testability. 17 tests covering auth redirect, org check, login redirect, session restore, title updates. Tests use real Pinia with `createMemoryHistory()`, mock only `fetchMe`.

**Files:**
- Modify: `web/src/router/index.ts`
- Create: `web/src/router/__tests__/guards.test.ts`

**Step 1:** Write the guard tests:

```typescript
// ABOUTME: Tests for route navigation guards.
// ABOUTME: Verifies auth redirect, org check, and login redirect behavior.

import { describe, it, expect, beforeEach, vi } from 'vitest'

// Test the guard logic functions in isolation.
// The actual guards call useAuthStore() — mock Pinia for testing.

describe('route guards', () => {
  it('redirects unauthenticated users to /login', () => {
    // Guard should return { name: 'login' } when not authenticated
  })

  it('preserves redirect query param when redirecting to login', () => {
    // Navigating to /watchlists unauthenticated should redirect to /login?redirect=/watchlists
  })

  it('redirects authenticated users away from login page', () => {
    // Authenticated user visiting /login should go to /cves
  })

  it('redirects to /create-org when user has no orgs', () => {
    // Authenticated user with empty orgs array
  })

  it('allows access when authenticated with active org', () => {
    // Normal authenticated flow
  })
})
```

**Step 2:** Implement the router. Replace `web/src/router/index.ts`:

```typescript
// ABOUTME: Vue Router configuration with auth and org guards.
// ABOUTME: Redirects unauthenticated users to login, org-less users to create-org.

import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    // ── Public routes ──────────────────────────────────────────────
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/LoginView.vue'),
      meta: { layout: 'public', requiresAuth: false },
    },
    {
      path: '/register',
      name: 'register',
      component: () => import('@/views/RegisterView.vue'),
      meta: { layout: 'public', requiresAuth: false },
    },
    {
      path: '/invitations/:token',
      name: 'invitation',
      component: () => import('@/views/InvitationView.vue'),
      meta: { layout: 'public', requiresAuth: false },
    },

    // ── Authenticated routes ───────────────────────────────────────
    {
      path: '/create-org',
      name: 'create-org',
      component: () => import('@/views/CreateOrgView.vue'),
      meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: false },
    },
    {
      path: '/cves',
      name: 'cve-search',
      component: () => import('@/views/CveSearchView.vue'),
      meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true },
    },
    {
      path: '/cves/:cveId',
      name: 'cve-detail',
      component: () => import('@/views/CveDetailView.vue'),
      meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true },
    },
    {
      path: '/watchlists',
      name: 'watchlists',
      component: () => import('@/views/WatchlistListView.vue'),
      meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true },
    },
    {
      path: '/watchlists/:id',
      name: 'watchlist-detail',
      component: () => import('@/views/WatchlistDetailView.vue'),
      meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true },
    },
    {
      path: '/settings/members',
      name: 'members',
      component: () => import('@/views/MembersView.vue'),
      meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true },
    },
    {
      path: '/settings/groups',
      name: 'groups',
      component: () => import('@/views/GroupsView.vue'),
      meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true },
    },
    {
      path: '/admin/feeds',
      name: 'feed-status',
      component: () => import('@/views/FeedStatusView.vue'),
      meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true },
    },

    // ── Redirects ──────────────────────────────────────────────────
    {
      path: '/',
      redirect: '/cves',
    },

    // ── 404 ────────────────────────────────────────────────────────
    {
      path: '/:pathMatch(.*)*',
      name: 'not-found',
      component: () => import('@/views/NotFoundView.vue'),
      meta: { layout: 'public', requiresAuth: false },
    },
  ],
})

// ── Navigation guards ───────────────────────────────────────────────────

router.beforeEach(async (to) => {
  const auth = useAuthStore()

  // Try to restore session on first navigation.
  if (!auth.isAuthenticated) {
    await auth.fetchMe()
  }

  const requiresAuth = to.meta.requiresAuth !== false
  const requiresOrg = to.meta.requiresOrg === true

  // Redirect unauthenticated users to login.
  if (requiresAuth && !auth.isAuthenticated) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }

  // Redirect authenticated users away from public-only pages.
  if (!requiresAuth && auth.isAuthenticated && (to.name === 'login' || to.name === 'register')) {
    return { name: 'cve-search' }
  }

  // Redirect to create-org if user has no orgs.
  if (requiresOrg && auth.isAuthenticated && auth.user?.orgs.length === 0) {
    return { name: 'create-org' }
  }

  // Redirect to org selector if user has orgs but none selected.
  // For now, auto-select first org. A proper org selector can be added later.
  if (requiresOrg && auth.isAuthenticated && !auth.activeOrgId && auth.user && auth.user.orgs.length > 0) {
    auth.setActiveOrg(auth.user.orgs[0].org_id)
  }
})

// Set document title from route name.
router.afterEach((to) => {
  const name = typeof to.name === 'string' ? to.name : ''
  const title = name
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
  document.title = title ? `${title} | CVErt Ops` : 'CVErt Ops'
})

export default router
```

**Step 3:** Run tests.

**Step 4:** Commit:

```bash
git add web/src/router/
git commit -m "feat(web): Vue Router with auth and org navigation guards"
```

---

### Task 18: Wire up App.vue with layouts ✅ `769684a`

> **Note:** Also cleaned up all Vue scaffold remnants (HelloWorld, Welcome, icons, logo, and their test). 55 tests passing.

**Files:**
- Modify: `web/src/App.vue`
- Modify: `web/src/main.ts`

**Step 1:** Update `web/src/App.vue` to use layout switching:

```vue
<!-- ABOUTME: Root application component with dynamic layout switching. -->
<!-- ABOUTME: Selects PublicLayout or AuthenticatedLayout based on route meta. -->

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import PublicLayout from '@/layouts/PublicLayout.vue'
import AuthenticatedLayout from '@/layouts/AuthenticatedLayout.vue'
import { Toaster } from '@/components/ui/sonner'

const route = useRoute()

const layout = computed(() => {
  return route.meta.layout === 'public' ? PublicLayout : AuthenticatedLayout
})
</script>

<template>
  <component :is="layout">
    <RouterView />
  </component>
  <Toaster />
</template>
```

**Step 2:** Verify `web/src/main.ts` imports Pinia, Router, and the global CSS:

```typescript
// ABOUTME: Application entry point — initializes Vue, Pinia, and Router.
// ABOUTME: Mounts the app to the DOM.

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import './assets/main.css'

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')
```

**Step 3:** Commit:

```bash
git add web/src/App.vue web/src/main.ts
git commit -m "feat(web): wire up App.vue with layout switching and Sonner toasts"
```

---

## Phase D: Page Views

For each page below, the implementing agent should:
1. Add any needed shadcn-vue components (`npx shadcn-vue@latest add ...`)
2. Invoke `/frontend-design` skill for the page's visual design
3. Write component tests (Vitest + Vue Test Utils)
4. Implement the component following TDD
5. Commit after each page

### Task 19: Create stub views for all routes ✅ `aa9ec20`

> **Deviation:** Executed before Task 17 (not after) so router lazy imports could resolve. Also removed unused scaffold views (AboutView, HomeView).

**Files:**
- Create stub `.vue` files for every route to prevent router import errors

**Step 1:** Create minimal stub views for all routes. Each stub should be a simple component with the page name:

```bash
mkdir -p web/src/views
```

Create each file with this pattern (example for `LoginView.vue`):

```vue
<!-- ABOUTME: Login page — email/password form with OAuth buttons. -->
<!-- ABOUTME: Redirects authenticated users to CVE search. -->

<template>
  <div>
    <h2>Login</h2>
    <p>TODO: implement</p>
  </div>
</template>
```

Create stubs for:
- `web/src/views/LoginView.vue`
- `web/src/views/RegisterView.vue`
- `web/src/views/InvitationView.vue`
- `web/src/views/CreateOrgView.vue`
- `web/src/views/CveSearchView.vue`
- `web/src/views/CveDetailView.vue`
- `web/src/views/WatchlistListView.vue`
- `web/src/views/WatchlistDetailView.vue`
- `web/src/views/MembersView.vue`
- `web/src/views/GroupsView.vue`
- `web/src/views/FeedStatusView.vue`
- `web/src/views/NotFoundView.vue`

**Step 2:** Verify the app compiles and routes work:

```bash
cd web && npm run dev
```

Navigate to each route — verify stubs render.

**Step 3:** Commit:

```bash
git add web/src/views/
git commit -m "feat(web): stub views for all routes"
```

---

### Task 20: Login page

**Files:**
- Modify: `web/src/views/LoginView.vue`
- Create: `web/src/views/__tests__/LoginView.test.ts`

**Step 1:** Add shadcn-vue form components if not already present:

```bash
cd web && npx shadcn-vue@latest add form
```

**Step 2:** Use `/frontend-design` skill to design the login page. Requirements:

- Email and password fields with labels
- "Log in" button (disabled while submitting)
- "Forgot password?" link (disabled/placeholder — deferred feature)
- Divider ("or continue with")
- GitHub OAuth button → navigates to `/api/v1/auth/oauth/github`
- Google OAuth button → navigates to `/api/v1/auth/oauth/google`
- "Don't have an account? Register" link → `/register`
- Error message display (invalid credentials, rate limited, etc.)
- Handles `?redirect=` query param — after successful login, navigates to redirect URL

**Step 3:** Write tests:

```typescript
// web/src/views/__tests__/LoginView.test.ts
// Tests:
// - Renders email and password inputs
// - Renders login button
// - Renders OAuth buttons (GitHub, Google)
// - Renders register link
// - Shows error message on failed login
// - Disables button during submission
// - Calls auth store login on submit
// - Navigates to redirect URL after successful login
// - Navigates to /cves after successful login (no redirect param)
```

**Step 4:** Implement the component following TDD — write each test, make it pass.

**Step 5:** Commit:

```bash
git add web/src/views/LoginView.vue web/src/views/__tests__/LoginView.test.ts
git commit -m "feat(web): Login page with email/password and OAuth"
```

---

### Task 21: Register page

**Files:**
- Modify: `web/src/views/RegisterView.vue`
- Create: `web/src/views/__tests__/RegisterView.test.ts`

**Step 1:** Use `/frontend-design` skill. Requirements:

- Email, password, confirm password, display name (optional) fields
- Password requirements hint (16+ characters per backend)
- "Register" button
- OAuth buttons (same as login)
- "Already have an account? Log in" link → `/login`
- Error display: email taken (409), invite-only mode (403 → "Registration is invite-only. Contact your administrator."), validation errors
- On success: auto-login (call `/auth/login` after register), then normal auth flow

**Step 2:** Write tests, implement TDD.

**Step 3:** Commit:

```bash
git add web/src/views/RegisterView.vue web/src/views/__tests__/RegisterView.test.ts
git commit -m "feat(web): Register page with invite-only handling"
```

---

### Task 22: Create Organization page

**Files:**
- Modify: `web/src/views/CreateOrgView.vue`
- Create: `web/src/views/__tests__/CreateOrgView.test.ts`

**Step 1:** Requirements:

- Simple form: organization name (required)
- "Create Organization" button
- On success: set active org in auth store, navigate to `/cves`
- Error handling for API failures
- Only shown to users with no orgs (route guard handles this)

**Step 2:** Write tests, implement TDD.

**Step 3:** Commit:

```bash
git add web/src/views/CreateOrgView.vue web/src/views/__tests__/CreateOrgView.test.ts
git commit -m "feat(web): Create Organization page"
```

---

### Task 23: CVE Search page

**Files:**
- Modify: `web/src/views/CveSearchView.vue`
- Create: `web/src/components/cve/CveSearchFilters.vue`
- Create: `web/src/components/cve/CveResultsTable.vue`
- Create: `web/src/composables/usePagination.ts`
- Create tests for each component

**Step 1:** Add shadcn-vue components:

```bash
cd web && npx shadcn-vue@latest add table badge select pagination skeleton
```

**Step 2:** Use `/frontend-design` skill. This is the most complex page. Requirements:

- **Search bar** at top — text search, submits on Enter
- **Filters panel** — severity (critical/high/medium/low), date range, status. Filters reflected in URL query params (`/cves?severity=critical&q=apache`)
- **Results table** — columns: CVE ID (link to detail), description (truncated), CVSS score (colored badge), EPSS score, status, date modified. Sorted by `date_modified_canonical` desc.
- **Keyset pagination** — "Next"/"Previous" buttons using cursor-based pagination from the API. Show page info ("Showing 1-25").
- **Loading skeletons** while fetching
- **Empty state** when no results
- URL state sync — filters and cursor in query params, updated on navigation. Browser back/forward works.

**API endpoints:**
- `GET /api/v1/cves` — with query params: `q`, `severity`, `status`, `cursor`, `limit`

**Step 3:** Create `usePagination` composable for keyset pagination logic (shared across list pages).

**Step 4:** Write tests, implement TDD.

**Step 5:** Commit:

```bash
git add web/src/views/CveSearchView.vue web/src/components/cve/ web/src/composables/
git commit -m "feat(web): CVE Search page with filters and keyset pagination"
```

---

### Task 24: CVE Detail page

**Files:**
- Modify: `web/src/views/CveDetailView.vue`
- Create: `web/src/components/cve/CveScoreCard.vue`
- Create: `web/src/components/cve/CveSourceComparison.vue`
- Create tests

**Step 1:** Add shadcn-vue components:

```bash
cd web && npx shadcn-vue@latest add tabs
```

**Step 2:** Use `/frontend-design` skill. Requirements:

- **Header** — CVE ID, status badge, date published/modified
- **Score cards** — CVSS score (with severity color), EPSS score (with percentile), KEV status
- **Description** — full text
- **Affected products/packages** — list/table of CPEs or affected package names
- **References** — list of URLs as links
- **Source comparison tab** — shows data from each feed source side-by-side (calls `GET /api/v1/cves/{cve_id}/sources`)
- **Loading skeleton** while fetching
- **404 handling** — CVE not found

**API endpoints:**
- `GET /api/v1/cves/{cve_id}`
- `GET /api/v1/cves/{cve_id}/sources`

**Step 3:** Write tests, implement TDD.

**Step 4:** Commit:

```bash
git add web/src/views/CveDetailView.vue web/src/components/cve/
git commit -m "feat(web): CVE Detail page with scores and source comparison"
```

---

### Task 25: Watchlist List page

**Files:**
- Modify: `web/src/views/WatchlistListView.vue`
- Create: `web/src/components/watchlist/CreateWatchlistDialog.vue`
- Create tests

**Step 1:** Add shadcn-vue components:

```bash
cd web && npx shadcn-vue@latest add dialog
```

**Step 2:** Use `/frontend-design` skill. Requirements:

- **Watchlist table/cards** — name, description, item count, last updated, actions (edit, delete)
- **"New Watchlist" button** → opens dialog with name + description fields
- **Empty state** for new users — "Create your first watchlist to track vulnerabilities"
- **Delete confirmation** dialog
- **Loading skeleton**

**API endpoints:**
- `GET /api/v1/orgs/{org_id}/watchlists`
- `POST /api/v1/orgs/{org_id}/watchlists`
- `DELETE /api/v1/orgs/{org_id}/watchlists/{id}`

Note: `{org_id}` comes from `useAuthStore().activeOrgId`.

**Step 3:** Write tests, implement TDD.

**Step 4:** Commit:

```bash
git add web/src/views/WatchlistListView.vue web/src/components/watchlist/
git commit -m "feat(web): Watchlist List page with create dialog"
```

---

### Task 26: Watchlist Detail page

**Files:**
- Modify: `web/src/views/WatchlistDetailView.vue`
- Create: `web/src/components/watchlist/WatchlistItemRow.vue`
- Create: `web/src/components/watchlist/AddItemDialog.vue`
- Create tests

**Step 1:** Use `/frontend-design` skill. Requirements:

- **Watchlist header** — name (editable inline or via edit button), description
- **Items table** — each item shows the CVE ID (link to detail), description, severity. Remove button per item.
- **"Add Item" button** → dialog with CVE ID input (or search)
- **Edit watchlist** — inline name/description editing
- **Back to watchlists** link
- **Loading skeleton**

**API endpoints:**
- `GET /api/v1/orgs/{org_id}/watchlists/{id}`
- `PATCH /api/v1/orgs/{org_id}/watchlists/{id}`
- `GET /api/v1/orgs/{org_id}/watchlists/{id}/items`
- `POST /api/v1/orgs/{org_id}/watchlists/{id}/items`
- `DELETE /api/v1/orgs/{org_id}/watchlists/{id}/items`

**Step 2:** Write tests, implement TDD.

**Step 3:** Commit:

```bash
git add web/src/views/WatchlistDetailView.vue web/src/components/watchlist/
git commit -m "feat(web): Watchlist Detail page with item management"
```

---

### Task 27: Members page

**Files:**
- Modify: `web/src/views/MembersView.vue`
- Create: `web/src/components/settings/InviteMemberDialog.vue`
- Create: `web/src/components/settings/RoleSelect.vue`
- Create tests

**Step 1:** Add shadcn-vue components:

```bash
cd web && npx shadcn-vue@latest add alert-dialog
```

**Step 2:** Use `/frontend-design` skill. Requirements:

- **Members table** — email, display name, role (badge), joined date, actions
- **Role column** — dropdown to change role (admin+ only). Constrained: can't elevate above own role, can't change sole owner
- **"Invite Member" button** → dialog with email + role select. Returns 202 always (no user enumeration).
- **Pending invitations section** — list of outstanding invitations with cancel button
- **Remove member** — confirmation dialog. Can't remove sole owner.
- **RBAC-aware** — hide/disable actions based on user's role in the org

**API endpoints:**
- `GET /api/v1/orgs/{org_id}/members`
- `POST /api/v1/orgs/{org_id}/invitations`
- `GET /api/v1/orgs/{org_id}/invitations`
- `DELETE /api/v1/orgs/{org_id}/invitations/{id}`
- `PATCH /api/v1/orgs/{org_id}/members/{user_id}` (role change)
- `DELETE /api/v1/orgs/{org_id}/members/{user_id}`

**Step 3:** Write tests, implement TDD.

**Step 4:** Commit:

```bash
git add web/src/views/MembersView.vue web/src/components/settings/
git commit -m "feat(web): Members page with invitations and role management"
```

---

### Task 28: Groups page

**Files:**
- Modify: `web/src/views/GroupsView.vue`
- Create: `web/src/components/settings/GroupDialog.vue`
- Create: `web/src/components/settings/GroupMembersDialog.vue`
- Create tests

**Step 1:** Use `/frontend-design` skill. Requirements:

- **Groups table** — name, description, member count, actions (edit, manage members, delete)
- **"New Group" button** → dialog with name + description
- **Edit group** → same dialog, pre-filled
- **Manage members** → dialog showing current members with remove, add member select
- **Delete group** → confirmation dialog
- **RBAC-aware** — admin+ only for write actions

**API endpoints:**
- `GET /api/v1/orgs/{org_id}/groups`
- `POST /api/v1/orgs/{org_id}/groups`
- `GET/PATCH/DELETE /api/v1/orgs/{org_id}/groups/{group_id}`
- `GET/POST/DELETE /api/v1/orgs/{org_id}/groups/{group_id}/members`

**Step 2:** Write tests, implement TDD.

**Step 3:** Commit:

```bash
git add web/src/views/GroupsView.vue web/src/components/settings/
git commit -m "feat(web): Groups page with member management"
```

---

### Task 29: Feed Status page

**Files:**
- Modify: `web/src/views/FeedStatusView.vue`
- Create tests

**Step 1:** Use `/frontend-design` skill. Requirements:

- **Feed status table** — feed name, last run time (relative + absolute), status (success/error/running as colored badge), records fetched, duration, error message (if any)
- **"Run Now" button** per feed → calls `POST /api/v1/admin/feeds/{feed}/run`
- **Auto-refresh** — poll feed status every 30 seconds (or manual refresh button)
- **Loading skeleton**

**API endpoints:**
- `GET /api/v1/admin/feeds`
- `POST /api/v1/admin/feeds/{feed}/run`

**Step 2:** Write tests, implement TDD.

**Step 3:** Commit:

```bash
git add web/src/views/FeedStatusView.vue web/src/views/__tests__/
git commit -m "feat(web): Feed Status admin page"
```

---

### Task 30: Invitation Acceptance page

**Files:**
- Modify: `web/src/views/InvitationView.vue`
- Create tests

**Step 1:** Use `/frontend-design` skill. Requirements:

- Reads `token` from route params
- Calls `GET /api/v1/auth/invitations/{token}` to get invitation info (org name, role, expiry)
- **If not authenticated:** shows invitation info + "Log in to accept" button (links to `/login?redirect=/invitations/{token}`)
- **If authenticated:** shows invitation info + "Accept Invitation" button → calls `POST /api/v1/auth/invitations/{token}/accept`
- **On success:** re-fetch `/auth/me` (to get updated org list), set new org as active, redirect to `/cves`
- **Error states:** expired invitation, already accepted, invalid token

**Step 2:** Write tests, implement TDD.

**Step 3:** Commit:

```bash
git add web/src/views/InvitationView.vue web/src/views/__tests__/
git commit -m "feat(web): Invitation acceptance page"
```

---

### Task 31: 404 page

**Files:**
- Modify: `web/src/views/NotFoundView.vue`

**Step 1:** Simple page:

```vue
<!-- ABOUTME: 404 page for unknown routes. -->
<!-- ABOUTME: Shows a message and link back to the dashboard. -->

<script setup lang="ts">
import { Button } from '@/components/ui/button'
</script>

<template>
  <div class="flex min-h-[50vh] flex-col items-center justify-center gap-4">
    <h1 class="text-4xl font-bold">404</h1>
    <p class="text-muted-foreground">Page not found</p>
    <Button as-child>
      <RouterLink to="/cves">Back to Dashboard</RouterLink>
    </Button>
  </div>
</template>
```

**Step 2:** Commit:

```bash
git add web/src/views/NotFoundView.vue
git commit -m "feat(web): 404 page"
```

---

## Phase E: Polish

### Task 32: Loading skeletons and empty states

**Files:**
- Create: `web/src/components/LoadingSkeleton.vue`
- Create: `web/src/components/EmptyState.vue`

**Step 1:** Add shadcn-vue skeleton:

```bash
cd web && npx shadcn-vue@latest add skeleton
```

**Step 2:** Create reusable `LoadingSkeleton.vue` — a generic skeleton layout that can be used by any page. Uses shadcn-vue's Skeleton component.

**Step 3:** Create reusable `EmptyState.vue` — accepts title, description, and optional action slot:

```vue
<!-- ABOUTME: Reusable empty state component for pages with no data. -->
<!-- ABOUTME: Shows a message and optional action button. -->

<script setup lang="ts">
defineProps<{
  title: string
  description: string
}>()
</script>

<template>
  <div class="flex min-h-[30vh] flex-col items-center justify-center gap-3 text-center">
    <h3 class="text-lg font-medium">{{ title }}</h3>
    <p class="max-w-md text-sm text-muted-foreground">{{ description }}</p>
    <div v-if="$slots.action" class="mt-2">
      <slot name="action" />
    </div>
  </div>
</template>
```

**Step 4:** Ensure each page view uses these components appropriately:
- Loading skeleton shown while initial data fetches
- Empty state shown when the data set is empty

**Step 5:** Commit:

```bash
git add web/src/components/LoadingSkeleton.vue web/src/components/EmptyState.vue
git commit -m "feat(web): reusable loading skeleton and empty state components"
```

---

### Task 33: Global error handler

**Files:**
- Modify: `web/src/main.ts`
- Create: `web/src/components/ErrorAlert.vue`

**Step 1:** Add shadcn-vue alert:

```bash
cd web && npx shadcn-vue@latest add alert
```

**Step 2:** Add global error handler to `web/src/main.ts`:

```typescript
app.config.errorHandler = (err, instance, info) => {
  console.error('Unhandled error:', err, info)
  // In production, this could report to an error tracking service.
}
```

**Step 3:** Create `ErrorAlert.vue` — a reusable error display component:

```vue
<!-- ABOUTME: Reusable error alert for displaying API or page errors. -->
<!-- ABOUTME: Shows error message with optional retry button. -->

<script setup lang="ts">
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

defineProps<{
  title?: string
  message: string
}>()

const emit = defineEmits<{
  retry: []
}>()
</script>

<template>
  <Alert variant="destructive">
    <AlertTitle>{{ title ?? 'Error' }}</AlertTitle>
    <AlertDescription class="flex items-center justify-between">
      <span>{{ message }}</span>
      <Button v-if="$attrs.onRetry" variant="outline" size="sm" @click="emit('retry')">
        Retry
      </Button>
    </AlertDescription>
  </Alert>
</template>
```

**Step 4:** Commit:

```bash
git add web/src/main.ts web/src/components/ErrorAlert.vue
git commit -m "feat(web): global error handler and reusable error alert"
```

---

### Task 34: Final lint, type-check, and test run

**Step 1:** Run all frontend checks:

```bash
cd web && npm run lint
cd web && npm run type-check
cd web && npm run test -- --run
```

Fix any issues.

**Step 2:** Run the Go tests (ensure SPA handler doesn't break anything):

```bash
go test ./... -count=1
```

**Step 3:** Build production bundle and verify:

```bash
cd web && npm run build
go build ./cmd/cvert-ops
```

**Step 4:** Commit any fixes:

```bash
git add -A
git commit -m "fix(web): lint and type-check fixes"
```

---

### Task 35: Remove smoke test

**Files:**
- Delete: `web/src/components/__tests__/smoke.test.ts`

**Step 1:** Remove the smoke test created in Task 5 (it's superseded by real component tests):

```bash
rm web/src/components/__tests__/smoke.test.ts
```

**Step 2:** Commit:

```bash
git add web/src/components/__tests__/smoke.test.ts
git commit -m "chore(web): remove setup smoke test"
```

---

## Summary

| Phase | Tasks | What it builds |
|-------|-------|---------------|
| A: Foundation | 1–10 | Vue scaffold, Tailwind, shadcn-vue, embed.go, SPA handler, config |
| B: API + Auth | 11–14 | Generated API types, typed client with CSRF/refresh, auth + UI stores |
| C: Layout + Routing | 15–19 | Layouts, sidebar, router with guards, stub views |
| D: Pages | 20–31 | Login, Register, Create Org, CVE Search/Detail, Watchlists, Members, Groups, Feed Status, Invitations, 404 |
| E: Polish | 32–35 | Loading skeletons, empty states, error handling, final checks |

**Total: ~35 tasks, ~50+ commits**

Each page task (Phase D) invokes `/frontend-design` for distinctive visual design. Infrastructure tasks (Phase A-C) have exact code. All tasks follow TDD.
