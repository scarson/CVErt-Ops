// ABOUTME: Tests for AdminSystemView — verifies doctor 503 responses are parsed as valid data.
// ABOUTME: Covers the edge case where /admin/doctor returns 503 with valid JSON when unhealthy.

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ path: '/admin/system' })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

const mockGET = vi.fn()

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: (...args: unknown[]) => mockGET(...args),
  },
}))

const doctorData = {
  status: 'unhealthy',
  checks: [
    { name: 'database', status: 'pass', message: 'connected' },
    { name: 'feeds', status: 'fail', message: 'stale data' },
  ],
}

const versionData = {
  version: '1.0.0',
  commit: 'abc123',
  build_time: '2026-03-16T00:00:00Z',
  go_version: 'go1.26',
}

const configData = {
  registration_mode: 'invite-only',
}

async function mountView() {
  const { default: AdminSystemView } = await import(
    '@/views/admin/AdminSystemView.vue'
  )
  return mount(AdminSystemView, {
    global: {
      stubs: {
        Card: { template: '<div><slot /></div>' },
        CardHeader: { template: '<div><slot /></div>' },
        CardTitle: { template: '<div><slot /></div>' },
        CardContent: { template: '<div><slot /></div>' },
        Badge: { template: '<span><slot /></span>' },
        Button: {
          template: '<button @click="$emit(\'click\')"><slot /></button>',
        },
        Loader2: { template: '<span />' },
        RefreshCcw: { template: '<span />' },
      },
    },
  })
}

describe('AdminSystemView', () => {
  let fetchSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.resetModules()
    mockGET.mockReset()
    fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('renders doctor results when endpoint returns 503 (unhealthy)', async () => {
    // Version: success
    mockGET.mockResolvedValueOnce({ data: versionData, error: undefined })
    // Config: success
    mockGET.mockResolvedValueOnce({ data: configData, error: undefined })

    // Doctor: 503 with valid JSON body
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(doctorData), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const wrapper = await mountView()
    await flushPromises()

    // Doctor data should be rendered — 503 is valid, not an error
    expect(wrapper.text()).toContain('unhealthy')
    expect(wrapper.text()).toContain('database')
    expect(wrapper.text()).toContain('feeds')
    expect(wrapper.text()).toContain('stale data')

    // Should NOT show the global error
    expect(wrapper.text()).not.toContain('Failed to load system information')
  })

  it('shows global error when ALL three calls fail', async () => {
    // Version: error
    mockGET.mockResolvedValueOnce({
      data: undefined,
      error: { status: 500, detail: 'server error' },
    })
    // Config: error
    mockGET.mockResolvedValueOnce({
      data: undefined,
      error: { status: 500, detail: 'server error' },
    })

    // Doctor: 500 (not 200 or 503 — a real failure)
    fetchSpy.mockResolvedValueOnce(
      new Response('Internal Server Error', {
        status: 500,
        headers: { 'Content-Type': 'text/plain' },
      }),
    )

    const wrapper = await mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Failed to load system information')
  })

  it('updates doctor results when runDoctor gets 503 response', async () => {
    // Initial load: all succeed with doctor healthy (200)
    mockGET.mockResolvedValueOnce({ data: versionData, error: undefined })
    mockGET.mockResolvedValueOnce({ data: configData, error: undefined })
    fetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ status: 'healthy', checks: [] }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    const wrapper = await mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('healthy')

    // Click "Run" button to re-run doctor — returns 503 this time
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(doctorData), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const runButton = wrapper.find('button')
    await runButton.trigger('click')
    await flushPromises()

    // Should show updated unhealthy data
    expect(wrapper.text()).toContain('unhealthy')
    expect(wrapper.text()).toContain('feeds')
    expect(wrapper.text()).toContain('stale data')
  })

  it('does NOT populate doctor data on 500 — only 200 and 503 are valid', async () => {
    // Version: success
    mockGET.mockResolvedValueOnce({ data: versionData, error: undefined })
    // Config: success
    mockGET.mockResolvedValueOnce({ data: configData, error: undefined })

    // Doctor: 500 (a real error, not unhealthy-but-valid like 503)
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(doctorData), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const wrapper = await mountView()
    await flushPromises()

    // Doctor data should NOT be rendered on 500
    expect(wrapper.text()).not.toContain('unhealthy')
    expect(wrapper.text()).not.toContain('stale data')

    // Version and config should still render (they succeeded)
    expect(wrapper.text()).toContain('1.0.0')
    expect(wrapper.text()).toContain('invite-only')
  })
})
