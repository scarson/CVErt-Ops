// ABOUTME: Tests for the CVE search filters component.
// ABOUTME: Covers search input rendering, severity filter, and event emission.

import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'

vi.mock('vue-router', () => ({
  useRoute: vi.fn<() => unknown>(() => ({ query: {} })),
  useRouter: vi.fn<() => unknown>(() => ({ push: vi.fn<(...args: unknown[]) => unknown>() })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

async function mountFilters(props = {}) {
  const { default: CveSearchFilters } = await import('@/components/cve/CveSearchFilters.vue')
  return mount(CveSearchFilters, {
    props: {
      query: '',
      severity: '',
      ...props,
    },
  })
}

describe('CveSearchFilters', () => {
  describe('rendering', () => {
    it('renders a search input', async () => {
      const wrapper = await mountFilters()

      const input = wrapper.find('input[type="search"]')
      expect(input.exists()).toBe(true)
    })

    it('renders with the provided query value', async () => {
      const wrapper = await mountFilters({ query: 'apache' })

      const input = wrapper.find('input[type="search"]')
      expect((input.element as HTMLInputElement).value).toBe('apache')
    })

    it('renders a search button', async () => {
      const wrapper = await mountFilters()

      const button = wrapper.find('button[type="submit"]')
      expect(button.exists()).toBe(true)
    })

    it('renders severity filter options', async () => {
      const wrapper = await mountFilters()

      const text = wrapper.text()
      expect(text).toContain('Severity')
    })
  })

  describe('events', () => {
    it('emits search event on form submit', async () => {
      const wrapper = await mountFilters()

      await wrapper.find('input[type="search"]').setValue('log4j')
      await wrapper.find('form').trigger('submit')

      const events = wrapper.emitted('search')
      expect(events).toBeDefined()
      expect(events![0]).toEqual([{ query: 'log4j', severity: '' }])
    })

    it('emits search with severity when severity is set via prop', async () => {
      const wrapper = await mountFilters({ query: 'apache', severity: 'critical' })

      await wrapper.find('form').trigger('submit')

      const events = wrapper.emitted('search')
      expect(events).toBeDefined()
      expect(events![0]).toEqual([{ query: 'apache', severity: 'critical' }])
    })

    it('emits search on Enter key in search input', async () => {
      const wrapper = await mountFilters()

      const input = wrapper.find('input[type="search"]')
      await input.setValue('openssl')
      await wrapper.find('form').trigger('submit')

      const events = wrapper.emitted('search')
      expect(events).toBeDefined()
    })
  })
})
