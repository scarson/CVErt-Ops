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

// Prevents multiple concurrent refresh calls when several API requests
// receive 401 simultaneously.
let refreshPromise: Promise<boolean> | null = null

export async function refreshTokens(): Promise<boolean> {
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

// Attempts token refresh on 401 responses, then retries the original request.
export const refreshMiddleware: Middleware = {
  async onResponse({ request, response }) {
    if (response.status !== 401) {
      return response
    }

    // Don't try to refresh the refresh or login endpoints themselves.
    if (request.url.includes('/auth/refresh') || request.url.includes('/auth/login')) {
      return response
    }

    // Coalesce concurrent refresh attempts.
    if (!refreshPromise) {
      refreshPromise = refreshTokens()
    }

    const success = await refreshPromise
    refreshPromise = null

    if (!success) {
      window.location.href = '/login'
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
