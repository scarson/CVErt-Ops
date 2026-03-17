// ABOUTME: Tests for the feed status dashboard — validates feed listing, status badges, and run triggers.
// ABOUTME: Mocks the typed API client to return feed status data and verifies component rendering and interactions.

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

const mockGET = vi.fn()
const mockPOST = vi.fn()

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: (...args: unknown[]) => mockGET(...args),
    POST: (...args: unknown[]) => mockPOST(...args),
  },
}))

const mockFeedItems = [
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
]

function mockFeedsSuccess() {
  mockGET.mockResolvedValueOnce({
    data: { items: mockFeedItems },
    error: undefined,
  })
}

function mockFeedsError() {
  mockGET.mockResolvedValueOnce({
    data: undefined,
    error: { status: 500, detail: 'server error' },
  })
}

async function mountFeedStatus() {
  const { default: FeedStatusView } = await import('@/views/FeedStatusView.vue')
  const wrapper = mount(FeedStatusView)
  await flushPromises()
  return wrapper
}

describe('FeedStatusView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGET.mockReset()
    mockPOST.mockReset()
    mockFeedsSuccess()
  })

  afterEach(() => {
    vi.restoreAllMocks()
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
    const wrapper = await mountFeedStatus()

    // Mock the POST trigger response
    mockPOST.mockResolvedValueOnce({
      data: { job_id: 'test-job-id' },
      error: undefined,
    })
    // Mock the refresh GET after trigger
    mockFeedsSuccess()

    const runButtons = wrapper.findAll('[data-testid="run-feed-btn"]')
    expect(runButtons.length).toBeGreaterThan(0)
    await runButtons[0]!.trigger('click')
    await flushPromises()

    // Verify the POST was made with the correct path
    expect(mockPOST).toHaveBeenCalledWith(
      '/admin/feeds/{feed}/run',
      expect.objectContaining({
        params: { path: { feed: 'nvd' } },
      }),
    )
  })

  it('shows loading state', async () => {
    mockGET.mockReset()
    mockGET.mockImplementation(() => new Promise(() => {}))
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
    mockGET.mockReset()
    mockFeedsError()

    const wrapper = await mountFeedStatus()
    expect(wrapper.text()).toContain('Failed to load feed status')
  })
})
