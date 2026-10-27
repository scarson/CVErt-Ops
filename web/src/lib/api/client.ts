// ABOUTME: Typed API client for the CVErt Ops backend.
// ABOUTME: Auto-configured with CSRF header, 401 refresh interceptor, and network-failure handling.

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

// Builds the RFC 9457 problem response that stands in for a request that never
// reached the server, so callers see it through the same `error` branch as a
// server-side failure.
function networkErrorResponse(): Response {
  return new Response(
    JSON.stringify({
      type: 'about:blank',
      title: 'Network Error',
      status: 503,
      detail: 'Could not reach the server. Check your connection and try again.',
    }),
    { status: 503, headers: { 'Content-Type': 'application/problem+json' } },
  )
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
// receive 401 simultaneously.
let refreshPromise: Promise<boolean> | null = null

function coalescedRefresh(): Promise<boolean> {
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
    // A rejection here bypasses onError middleware, so network failures are converted in place.
    try {
      return await fetch(request.clone(), { credentials: 'include' })
    } catch (err) {
      if (request.signal.aborted) {
        throw err
      }
      return networkErrorResponse()
    }
  },
}

// Converts fetch rejections (server unreachable, offline, DNS failure) into a
// 503 problem response. Requests aborted by the caller still reject.
export const networkErrorMiddleware: Middleware = {
  onError({ request }) {
    if (request.signal.aborted) {
      return
    }
    return networkErrorResponse()
  },
}

const client = createClient<paths>({
  baseUrl: '/api/v1',
  credentials: 'include',
})

client.use(csrfMiddleware)
client.use(refreshMiddleware)
client.use(networkErrorMiddleware)

export default client
