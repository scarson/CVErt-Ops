// ABOUTME: Tests for the feed status dashboard — validates feed listing, status badges, and run triggers.
// ABOUTME: Mocks fetch to return feed status data and verifies component rendering and interactions.

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ path: '/admin/feeds' })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

const mockFeedData = {
  feeds: [
    {
      feed_name: 'nvd',
      last_success_at: '2026-03-07T10:00:00Z',
      last_attempt_at: '2026-03-07T10:00:00Z',
      consecutive_failures: 0,
      last_error: '',
      recent_logs: [
        {
          id: '00000000-0000-0000-0000-000000000001',
          started_at: '2026-03-07T09:58:00Z',
          ended_at: '2026-03-07T10:00:00Z',
          status: 'success',
          items_fetched: 150,
          items_upserted: 42,
        },
      ],
    },
    {
      feed_name: 'kev',
      last_success_at: '2026-03-06T08:00:00Z',
      last_attempt_at: '2026-03-07T08:00:00Z',
      consecutive_failures: 3,
      last_error: 'connection refused',
      recent_logs: [
        {
          id: '00000000-0000-0000-0000-000000000002',
          started_at: '2026-03-07T07:58:00Z',
          ended_at: '2026-03-07T08:00:00Z',
          status: 'error',
          items_fetched: 0,
          items_upserted: 0,
          error_summary: 'connection refused',
        },
      ],
    },
  ],
}

async function mountFeedStatus(fetchImpl?: typeof fetch) {
  if (fetchImpl) {
    vi.stubGlobal('fetch', fetchImpl)
  }
  const { default: FeedStatusView } = await import('@/views/FeedStatusView.vue')
  const wrapper = mount(FeedStatusView)
  await flushPromises()
  return wrapper
}

describe('FeedStatusView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockFeedData),
        }),
      ),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('renders the page title', async () => {
    const wrapper = await mountFeedStatus()
    expect(wrapper.text()).toContain('Feed Status')
  })

  it('renders the subtitle', async () => {
    const wrapper = await mountFeedStatus()
    expect(wrapper.text()).toContain('Monitor vulnerability data source health')
  })

  it('renders feed names from API data', async () => {
    const wrapper = await mountFeedStatus()
    expect(wrapper.text()).toContain('nvd')
    expect(wrapper.text()).toContain('kev')
  })

  it('shows healthy badge for feeds with zero failures', async () => {
    const wrapper = await mountFeedStatus()
    const text = wrapper.text()
    // NVD should show as healthy
    expect(text).toContain('Healthy')
  })

  it('shows failing badge for feeds with consecutive failures', async () => {
    const wrapper = await mountFeedStatus()
    const text = wrapper.text()
    // KEV should show as failing
    expect(text).toContain('Failing')
  })

  it('shows the last error for failing feeds', async () => {
    const wrapper = await mountFeedStatus()
    expect(wrapper.text()).toContain('connection refused')
  })

  it('renders Run Now button for each feed', async () => {
    const wrapper = await mountFeedStatus()
    const buttons = wrapper.findAll('[data-testid="run-feed-btn"]')
    expect(buttons.length).toBe(2)
  })

  it('sends POST on Run Now click', async () => {
    const fetchMock = vi.fn()
      // Initial list fetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockFeedData),
      })
      // Trigger POST
      .mockResolvedValueOnce({
        ok: true,
        status: 202,
        json: () => Promise.resolve({ job_id: 'test-job-id' }),
      })
      // Refresh list fetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockFeedData),
      })

    const wrapper = await mountFeedStatus(fetchMock as unknown as typeof fetch)
    const runButtons = wrapper.findAll('[data-testid="run-feed-btn"]')
    expect(runButtons.length).toBeGreaterThan(0)
    await runButtons[0]!.trigger('click')
    await flushPromises()

    // Verify the POST was made to the correct URL
    const postCall = fetchMock.mock.calls.find(
      (call: unknown[]) => (call[1] as RequestInit | undefined)?.method === 'POST',
    )
    expect(postCall).toBeTruthy()
    expect(postCall![0]).toContain('/api/v1/admin/feeds/nvd/run')
  })

  it('shows loading state', async () => {
    // Use a fetch that never resolves to keep loading state
    const neverResolve = vi.fn(() => new Promise(() => {}))
    vi.stubGlobal('fetch', neverResolve)
    const { default: FeedStatusView } = await import('@/views/FeedStatusView.vue')
    const wrapper = mount(FeedStatusView)
    expect(wrapper.text()).toContain('Loading')
  })

  it('expands log rows when chevron is clicked', async () => {
    const wrapper = await mountFeedStatus()
    // Log details should not be visible initially
    expect(wrapper.text()).not.toContain('150 fetched')

    // Click the expand button for the first feed (nvd has logs)
    const expandButtons = wrapper.findAll('button[aria-label^="Toggle logs"]')
    expect(expandButtons.length).toBeGreaterThan(0)

    await expandButtons[0]!.trigger('click')
    await flushPromises()

    // Log details should now be visible
    expect(wrapper.text()).toContain('150 fetched')
    expect(wrapper.text()).toContain('42 upserted')
  })

  it('collapses log rows when chevron is clicked again', async () => {
    const wrapper = await mountFeedStatus()

    const expandButtons = wrapper.findAll('button[aria-label^="Toggle logs"]')
    expect(expandButtons.length).toBeGreaterThan(0)
    // Expand
    await expandButtons[0]!.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('150 fetched')

    // Collapse
    await expandButtons[0]!.trigger('click')
    await flushPromises()
    expect(wrapper.text()).not.toContain('150 fetched')
  })

  it('shows error state on fetch failure', async () => {
    const failFetch = vi.fn(() =>
      Promise.resolve({
        ok: false,
        status: 500,
        json: () => Promise.resolve({ error: 'server error' }),
      }),
    )

    const wrapper = await mountFeedStatus(failFetch as unknown as typeof fetch)
    expect(wrapper.text()).toContain('Failed to load feed status')
  })
})
