// ABOUTME: Tests for the create organization page view.
// ABOUTME: Covers form rendering, API submission, error handling, and post-creation navigation.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { nextTick } from 'vue'

const mockPush = vi.fn()

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ query: {} })),
  useRouter: vi.fn(() => ({ push: mockPush })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn(),
    POST: vi.fn(),
  },
}))

import { useAuthStore } from '@/stores/auth'

async function mountCreateOrg() {
  const { default: CreateOrgView } = await import('@/views/CreateOrgView.vue')
  return mount(CreateOrgView)
}

describe('CreateOrgView', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()

    // Mock global fetch for the raw API call (not in openapi-fetch schema).
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })

  describe('rendering', () => {
    it('renders org name input', async () => {
      const wrapper = await mountCreateOrg()
      const nameInput = wrapper.find('#org-name')
      expect(nameInput.exists()).toBe(true)
    })

    it('renders create button', async () => {
      const wrapper = await mountCreateOrg()
      const button = wrapper.find('button[type="submit"]')
      expect(button.exists()).toBe(true)
      expect(button.text()).toContain('Create Organization')
    })
  })

  describe('form submission', () => {
    it('disables button while submitting', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'fetchMe').mockResolvedValue(true)
      vi.spyOn(auth, 'setActiveOrg')

      let resolvePost: (value: unknown) => void
      mockFetch.mockImplementation(
        () => new Promise((resolve) => { resolvePost = resolve }),
      )

      const wrapper = await mountCreateOrg()

      await wrapper.find('#org-name').setValue('My Org')
      await wrapper.find('form').trigger('submit')
      await nextTick()

      const submitButton = wrapper.find('button[type="submit"]')
      expect(submitButton.attributes('disabled')).toBeDefined()

      resolvePost!({
        ok: true,
        status: 201,
        json: () => Promise.resolve({ org_id: 'org-1', name: 'My Org' }),
      })
      await flushPromises()
    })

    it('calls API and navigates on success', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 201,
        json: () => Promise.resolve({ org_id: 'org-1', name: 'My Org' }),
      })

      const auth = useAuthStore()
      vi.spyOn(auth, 'fetchMe').mockResolvedValue(true)
      vi.spyOn(auth, 'setActiveOrg')

      const wrapper = await mountCreateOrg()

      await wrapper.find('#org-name').setValue('My Org')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith('/api/v1/orgs',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ name: 'My Org' }),
        }),
      )

      expect(auth.fetchMe).toHaveBeenCalled()
      expect(auth.setActiveOrg).toHaveBeenCalledWith('org-1')
      expect(mockPush).toHaveBeenCalledWith('/cves')
    })
  })

  describe('error handling', () => {
    it('shows RFC 9457 detail message on API failure', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 422,
        json: () => Promise.resolve({ detail: 'validation failed' }),
      })

      const wrapper = await mountCreateOrg()

      await wrapper.find('#org-name').setValue('My Org')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('validation failed')
      expect(mockPush).not.toHaveBeenCalled()
    })

    it('shows fallback error when response has no detail', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        json: () => Promise.resolve({}),
      })

      const wrapper = await mountCreateOrg()

      await wrapper.find('#org-name').setValue('My Org')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to create organization')
      expect(mockPush).not.toHaveBeenCalled()
    })
  })
})
