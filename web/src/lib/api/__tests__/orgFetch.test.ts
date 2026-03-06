// ABOUTME: Tests for the org-scoped fetch wrapper.
// ABOUTME: Verifies CSRF headers, credentials, 401 refresh+retry, and body-safe retry.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

describe('orgFetch', () => {
  let originalFetch: typeof globalThis.fetch
  let originalLocation: Location

  beforeEach(() => {
    originalFetch = globalThis.fetch
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
    vi.resetModules()
  })

  it('includes credentials on GET requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('[]', { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    await orgFetch('/api/v1/orgs/123/members')

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [, init] = fetchMock.mock.calls[0]!
    expect(init.credentials).toBe('include')
  })

  it('adds CSRF header to POST requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    await orgFetch('/api/v1/orgs/123/members', {
      method: 'POST',
      body: JSON.stringify({ user_id: 'abc' }),
    })

    const [, init] = fetchMock.mock.calls[0]!
    expect(init.headers.get('X-Requested-By')).toBe('CVErt-Ops')
    expect(init.headers.get('Content-Type')).toBe('application/json')
  })

  it('adds CSRF header to DELETE requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    await orgFetch('/api/v1/orgs/123/members/456', { method: 'DELETE' })

    const [, init] = fetchMock.mock.calls[0]!
    expect(init.headers.get('X-Requested-By')).toBe('CVErt-Ops')
  })

  it('does not add CSRF header to GET requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('[]', { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    await orgFetch('/api/v1/orgs/123/members')

    const [, init] = fetchMock.mock.calls[0]!
    expect(init.headers.get('X-Requested-By')).toBeNull()
  })

  it('retries on 401 after successful token refresh', async () => {
    const fetchMock = vi.fn()
    // 1st call: original request → 401
    fetchMock.mockResolvedValueOnce(new Response('unauthorized', { status: 401 }))
    // 2nd call: refresh → 200
    fetchMock.mockResolvedValueOnce(new Response('', { status: 200 }))
    // 3rd call: retry → 200
    fetchMock.mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    const resp = await orgFetch('/api/v1/orgs/123/members')

    expect(resp.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(3)
    // 2nd call should be the refresh
    expect(fetchMock.mock.calls[1]![0]).toBe('/api/v1/auth/refresh')
  })

  it('redirects to /login when refresh fails', async () => {
    const fetchMock = vi.fn()
    fetchMock.mockResolvedValueOnce(new Response('unauthorized', { status: 401 }))
    fetchMock.mockResolvedValueOnce(new Response('', { status: 401 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    const resp = await orgFetch('/api/v1/orgs/123/members')

    expect(resp.status).toBe(401)
    expect(window.location.href).toBe('/login')
  })

  it('preserves body on POST retry after 401 refresh (B4 fix)', async () => {
    const body = JSON.stringify({ role: 'admin' })
    const fetchMock = vi.fn()
    fetchMock.mockResolvedValueOnce(new Response('unauthorized', { status: 401 }))
    fetchMock.mockResolvedValueOnce(new Response('', { status: 200 }))
    fetchMock.mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }))
    globalThis.fetch = fetchMock

    const { orgFetch } = await import('../orgFetch')
    await orgFetch('/api/v1/orgs/123/members/456', {
      method: 'PATCH',
      body,
    })

    // 3rd call (retry) should have the body
    const retryInit = fetchMock.mock.calls[2]![1]
    expect(retryInit.body).toBe(body)
  })
})
