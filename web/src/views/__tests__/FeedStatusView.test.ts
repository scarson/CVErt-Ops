// ABOUTME: Tests for the feed status placeholder page.
// ABOUTME: Covers page title rendering and placeholder message display.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ path: '/admin/feeds' })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

async function mountFeedStatus() {
  const { default: FeedStatusView } = await import('@/views/FeedStatusView.vue')
  return mount(FeedStatusView)
}

describe('FeedStatusView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the page title', async () => {
    const wrapper = await mountFeedStatus()
    expect(wrapper.text()).toContain('Feed Status')
  })

  it('renders the subtitle', async () => {
    const wrapper = await mountFeedStatus()
    expect(wrapper.text()).toContain('Monitor vulnerability data source health')
  })

  it('shows the placeholder message', async () => {
    const wrapper = await mountFeedStatus()
    expect(wrapper.text()).toContain(
      'Feed monitoring will be available once feed adapters are configured.',
    )
  })

  it('shows the coming soon badge', async () => {
    const wrapper = await mountFeedStatus()
    expect(wrapper.text()).toContain('Coming soon')
  })
})
