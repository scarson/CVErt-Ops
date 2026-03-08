// ABOUTME: Tests for the 404 not found page.
// ABOUTME: Covers heading, message text, and navigation link back to dashboard.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ path: '/nonexistent' })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

async function mountNotFound() {
  const { default: NotFoundView } = await import('@/views/NotFoundView.vue')
  return mount(NotFoundView)
}

describe('NotFoundView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders "404" heading', async () => {
    const wrapper = await mountNotFound()
    const heading = wrapper.find('h1')
    expect(heading.exists()).toBe(true)
    expect(heading.text()).toBe('404')
  })

  it('renders "Page not found" text', async () => {
    const wrapper = await mountNotFound()
    expect(wrapper.text()).toContain('Page not found')
  })

  it('has a link back to /cves', async () => {
    const wrapper = await mountNotFound()
    const link = wrapper.find('a[href="/cves"]')
    expect(link.exists()).toBe(true)
    expect(link.text()).toContain('Back to Dashboard')
  })
})
