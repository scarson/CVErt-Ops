// ABOUTME: Tests for AdminSystemView doctor endpoint 503 response handling.
// ABOUTME: Verifies that both 200 and 503 doctor responses populate the health check data.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import AdminSystemView from '../AdminSystemView.vue'

const healthyDoctor = {
  status: 'healthy',
  checks: [
    { name: 'database', status: 'pass', message: 'connected' },
    { name: 'redis', status: 'pass', message: 'connected' },
  ],
}

const unhealthyDoctor = {
  status: 'unhealthy',
  checks: [
    { name: 'database', status: 'fail', message: 'connection refused' },
    { name: 'redis', status: 'pass', message: 'connected' },
  ],
}

// Stub the openapi-fetch client used by the component.
vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn().mockResolvedValue({ data: null, error: { status: 500 } }),
  },
}))

// Stub UI components to avoid importing the full shadcn-vue tree.
vi.mock('@/components/ui/button', () => ({
  Button: {
    name: 'Button',
    template: '<button><slot /></button>',
    props: ['variant', 'size', 'disabled'],
  },
}))

vi.mock('@/components/ui/card', () => ({
  Card: { name: 'Card', template: '<div><slot /></div>' },
  CardContent: { name: 'CardContent', template: '<div><slot /></div>' },
  CardHeader: { name: 'CardHeader', template: '<div><slot /></div>' },
  CardTitle: { name: 'CardTitle', template: '<div><slot /></div>' },
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: {
    name: 'Badge',
    template: '<span><slot /></span>',
    props: ['variant'],
  },
}))

vi.mock('lucide-vue-next', () => ({
  Loader2: { name: 'Loader2', template: '<span />' },
  RefreshCcw: { name: 'RefreshCcw', template: '<span />' },
}))

let fetchMock: ReturnType<typeof vi.fn>
let originalFetch: typeof globalThis.fetch

beforeEach(() => {
  originalFetch = globalThis.fetch
  fetchMock = vi.fn()
  globalThis.fetch = fetchMock
})

afterEach(() => {
  globalThis.fetch = originalFetch
  vi.restoreAllMocks()
})

describe('AdminSystemView doctor response handling', () => {
  it('populates doctor data from a 200 response', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(healthyDoctor), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const wrapper = mount(AdminSystemView)
    await flushPromises()

    expect(wrapper.text()).toContain('healthy')
    expect(wrapper.text()).toContain('database')
  })

  it('populates doctor data from a 503 response', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(unhealthyDoctor), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const wrapper = mount(AdminSystemView)
    await flushPromises()

    expect(wrapper.text()).toContain('unhealthy')
    expect(wrapper.text()).toContain('database')
    expect(wrapper.text()).toContain('connection refused')
  })

  it('handles 503 response when Run button is clicked', async () => {
    // Initial fetch returns 200 healthy.
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(healthyDoctor), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const wrapper = mount(AdminSystemView)
    await flushPromises()

    // Clicking Run triggers runDoctor() which issues a second fetch.
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(unhealthyDoctor), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const runButton = wrapper.find('button')
    await runButton.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('unhealthy')
    expect(wrapper.text()).toContain('connection refused')
  })

  it('does NOT populate doctor data on 500 — only 200 and 503 are valid', async () => {
    // Doctor: 500 (a real error, not unhealthy-but-valid like 503)
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(unhealthyDoctor), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const wrapper = mount(AdminSystemView)
    await flushPromises()

    // Doctor data should NOT be rendered on 500
    expect(wrapper.text()).not.toContain('unhealthy')
    expect(wrapper.text()).not.toContain('connection refused')
  })
})
