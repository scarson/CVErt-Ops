// ABOUTME: Typed API client for the CVErt Ops backend.
// ABOUTME: Auto-configured with CSRF header and 401 refresh interceptor.

import createClient, { type Middleware } from 'openapi-fetch'
import type { paths } from './schema'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

// Adds X-Requested-By header to state-changing requests.
// Required by the backend's csrfProtect middleware for cookie-authenticated requests.
export const csrfMiddleware: Middleware = {
  async onRequest({ request }) {
    if (!SAFE_METHODS.has(request.method.toUpperCase())) {
      request.headers.set('X-Requested-By', 'CVErt-Ops')
    }
    return request
  },
}

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

// Prevents multiple concurrent refresh calls when several API requests
// receive 401 simultaneously. Shared by the typed client middleware and orgFetch.
let refreshPromise: Promise<boolean> | null = null

export function coalescedRefresh(): Promise<boolean> {
  if (!refreshPromise) {
    refreshPromise = refreshTokens().finally(() => {
      refreshPromise = null
    })
  }
  return refreshPromise
}

// Attempts token refresh on 401 responses, then retries the original request.
export const refreshMiddleware: Middleware = {
  async onResponse({ request, response }) {
    if (response.status !== 401) {
      return response
    }

    // Don't try to refresh any auth endpoints — they're the auth system itself.
    if (request.url.includes('/auth/')) {
      return response
    }

    const success = await coalescedRefresh()

    if (!success) {
      return response
    }

    // Retry the original request with fresh cookies.
    // Clone the request before retrying — the original body stream was consumed by the first fetch.
    return fetch(request.clone(), { credentials: 'include' })
  },
}

const client = createClient<paths>({
  baseUrl: '/api/v1',
  credentials: 'include',
})

client.use(csrfMiddleware)
client.use(refreshMiddleware)

export default client
