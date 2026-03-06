// ABOUTME: Shared fetch wrapper for org-scoped API calls not in the OpenAPI schema.
// ABOUTME: Applies credentials, CSRF headers, and 401 refresh+retry — matching the typed client's middleware.

import { coalescedRefresh } from './client'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/**
 * Fetch wrapper for org-scoped endpoints that aren't in the OpenAPI schema.
 * Applies the same protections as the typed client:
 * - `credentials: 'include'` on every request
 * - `X-Requested-By: CVErt-Ops` on state-changing methods
 * - 401 → refresh token → retry (with body preservation)
 */
export async function orgFetch(
  url: string,
  init: RequestInit = {},
): Promise<Response> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)

  if (!SAFE_METHODS.has(method)) {
    headers.set('X-Requested-By', 'CVErt-Ops')
    if (!headers.has('Content-Type') && init.body) {
      headers.set('Content-Type', 'application/json')
    }
  }

  const resp = await fetch(url, {
    ...init,
    method,
    headers,
    credentials: 'include',
  })

  if (resp.status !== 401) {
    return resp
  }

  // Attempt token refresh (coalesced with typed client).
  const refreshed = await coalescedRefresh()

  if (!refreshed) {
    return resp
  }

  // Retry with the same parameters — body is a string (not a stream), so it's safe to reuse.
  return fetch(url, {
    ...init,
    method,
    headers,
    credentials: 'include',
  })
}
