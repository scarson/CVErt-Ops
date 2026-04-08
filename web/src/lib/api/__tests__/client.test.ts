// ABOUTME: Tests for the API client configuration.
// ABOUTME: Verifies CSRF header injection and 401 refresh interceptor behavior.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import type { MergedOptions } from 'openapi-fetch'

// Helper to build the MiddlewareCallbackParams shape that openapi-fetch expects.
function middlewareParams(request: Request) {
  return {
    request,
    schemaPath: '/test' as const,
    params: {},
    id: 'test-id',
    options: {} as MergedOptions,
  }
}

describe('CSRF middleware', () => {
  it('adds X-Requested-By header to POST requests', async () => {
    const { csrfMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/test', {
      method: 'POST',
    })
    const result = await csrfMiddleware.onRequest!(middlewareParams(request))
    expect((result as Request).headers.get('X-Requested-By')).toBe('CVErt-Ops')
  })

  it('adds X-Requested-By header to PUT requests', async () => {
    const { csrfMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/test', {
      method: 'PUT',
    })
    const result = await csrfMiddleware.onRequest!(middlewareParams(request))
    expect((result as Request).headers.get('X-Requested-By')).toBe('CVErt-Ops')
  })

  it('adds X-Requested-By header to PATCH requests', async () => {
    const { csrfMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/test', {
      method: 'PATCH',
    })
    const result = await csrfMiddleware.onRequest!(middlewareParams(request))
    expect((result as Request).headers.get('X-Requested-By')).toBe('CVErt-Ops')
  })

  it('adds X-Requested-By header to DELETE requests', async () => {
    const { csrfMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/test', {
      method: 'DELETE',
    })
    const result = await csrfMiddleware.onRequest!(middlewareParams(request))
    expect((result as Request).headers.get('X-Requested-By')).toBe('CVErt-Ops')
  })

  it('does not add X-Requested-By header to GET requests', async () => {
    const { csrfMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/test', {
      method: 'GET',
    })
    const result = await csrfMiddleware.onRequest!(middlewareParams(request))
    // For GET, the middleware returns the request unmodified (no header).
    expect((result as Request).headers.get('X-Requested-By')).toBeNull()
  })

  it('does not add X-Requested-By header to HEAD requests', async () => {
    const { csrfMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/test', {
      method: 'HEAD',
    })
    const result = await csrfMiddleware.onRequest!(middlewareParams(request))
    expect((result as Request).headers.get('X-Requested-By')).toBeNull()
  })

  it('does not add X-Requested-By header to OPTIONS requests', async () => {
    const { csrfMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/test', {
      method: 'OPTIONS',
    })
    const result = await csrfMiddleware.onRequest!(middlewareParams(request))
    expect((result as Request).headers.get('X-Requested-By')).toBeNull()
  })
})

describe('refresh middleware', () => {
  let originalFetch: typeof globalThis.fetch
  let originalLocation: Location

  beforeEach(() => {
    originalFetch = globalThis.fetch
    // Save and mock window.location for redirect tests.
    originalLocation = window.location
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { ...originalLocation, href: '' },
    })
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    Object.defineProperty(window, 'location', {
      writable: true,
      value: originalLocation,
    })
    vi.restoreAllMocks()
  })

  it('passes through non-401 responses unchanged', async () => {
    const { refreshMiddleware } = await import('../client')
    const request = new Request('http://localhost/api/v1/cves')
    const response = new Response('ok', { status: 200 })

    const result = await refreshMiddleware.onResponse!({
      ...middlewareParams(request),
      response,
    })

    expect((result as Response).status).toBe(200)
  })

  it('does not attempt refresh for auth endpoints', async () => {
    const { refreshMiddleware } = await import('../client')
    const fetchMock = vi.fn<typeof fetch>()
    globalThis.fetch = fetchMock

    const loginRequest = new Request('http://localhost/api/v1/auth/login')
    const loginResponse = new Response('unauthorized', { status: 401 })

    const result = await refreshMiddleware.onResponse!({
      ...middlewareParams(loginRequest),
      response: loginResponse,
    })

    expect((result as Response).status).toBe(401)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('does not attempt refresh for auth/me endpoint', async () => {
    const { refreshMiddleware } = await import('../client')
    const fetchMock = vi.fn<typeof fetch>()
    globalThis.fetch = fetchMock

    const meRequest = new Request('http://localhost/api/v1/auth/me')
    const meResponse = new Response('unauthorized', { status: 401 })

    const result = await refreshMiddleware.onResponse!({
      ...middlewareParams(meRequest),
      response: meResponse,
    })

    expect((result as Response).status).toBe(401)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('does not attempt refresh for the refresh endpoint itself', async () => {
    const { refreshMiddleware } = await import('../client')
    const fetchMock = vi.fn<typeof fetch>()
    globalThis.fetch = fetchMock

    const refreshRequest = new Request('http://localhost/api/v1/auth/refresh')
    const refreshResponse = new Response('unauthorized', { status: 401 })

    const result = await refreshMiddleware.onResponse!({
      ...middlewareParams(refreshRequest),
      response: refreshResponse,
    })

    expect((result as Response).status).toBe(401)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('attempts refresh and retries on 401 from a regular endpoint', async () => {
    const { refreshMiddleware } = await import('../client')
    const retryResponse = new Response('ok', { status: 200 })

    const fetchMock = vi.fn<typeof fetch>()
    // First call: refresh succeeds.
    fetchMock.mockResolvedValueOnce(new Response('', { status: 200 }))
    // Second call: retry the original request.
    fetchMock.mockResolvedValueOnce(retryResponse)
    globalThis.fetch = fetchMock

    const request = new Request('http://localhost/api/v1/cves')
    const response = new Response('unauthorized', { status: 401 })

    const result = await refreshMiddleware.onResponse!({
      ...middlewareParams(request),
      response,
    })

    // Refresh call should have been made.
    expect(fetchMock).toHaveBeenCalledTimes(2)
    // First call is the refresh.
    expect(fetchMock.mock.calls[0]![0]).toBe('/api/v1/auth/refresh')
    // The result should be the retry response.
    expect((result as Response).status).toBe(200)
  })

  it('returns original 401 response when refresh fails', async () => {
    const { refreshMiddleware } = await import('../client')

    const fetchMock = vi.fn<typeof fetch>()
    // Refresh returns 401 (failure).
    fetchMock.mockResolvedValueOnce(new Response('', { status: 401 }))
    globalThis.fetch = fetchMock

    const request = new Request('http://localhost/api/v1/cves')
    const response = new Response('unauthorized', { status: 401 })

    const result = await refreshMiddleware.onResponse!({
      ...middlewareParams(request),
      response,
    })

    expect((result as Response).status).toBe(401)
  })
})
