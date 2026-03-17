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

const mockPOST = vi.fn()

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn(),
    POST: (...args: unknown[]) => mockPOST(...args),
  },
}))

import { useAuthStore } from '@/stores/auth'

async function mountCreateOrg() {
  const { default: CreateOrgView } = await import('@/views/CreateOrgView.vue')
  return mount(CreateOrgView)
}

describe('CreateOrgView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()
    mockPOST.mockReset()
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
      mockPOST.mockImplementation(
        () => new Promise((resolve) => { resolvePost = resolve }),
      )

      const wrapper = await mountCreateOrg()

      await wrapper.find('#org-name').setValue('My Org')
      await wrapper.find('form').trigger('submit')
      await nextTick()

      const submitButton = wrapper.find('button[type="submit"]')
      expect(submitButton.attributes('disabled')).toBeDefined()

      resolvePost!({
        data: { org_id: 'org-1', name: 'My Org' },
        error: undefined,
      })
      await flushPromises()
    })

    it('calls API and navigates on success', async () => {
      mockPOST.mockResolvedValue({
        data: { org_id: 'org-1', name: 'My Org' },
        error: undefined,
      })

      const auth = useAuthStore()
      vi.spyOn(auth, 'fetchMe').mockResolvedValue(true)
      vi.spyOn(auth, 'setActiveOrg')

      const wrapper = await mountCreateOrg()

      await wrapper.find('#org-name').setValue('My Org')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(mockPOST).toHaveBeenCalledWith(
        '/orgs',
        expect.objectContaining({
          body: { name: 'My Org' },
        }),
      )

      expect(auth.fetchMe).toHaveBeenCalled()
      expect(auth.setActiveOrg).toHaveBeenCalledWith('org-1')
      expect(mockPush).toHaveBeenCalledWith('/cves')
    })
  })

  describe('error handling', () => {
    it('shows RFC 9457 detail message on API failure', async () => {
      mockPOST.mockResolvedValue({
        data: undefined,
        error: { status: 422, detail: 'validation failed' },
      })

      const wrapper = await mountCreateOrg()

      await wrapper.find('#org-name').setValue('My Org')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('validation failed')
      expect(mockPush).not.toHaveBeenCalled()
    })

    it('shows fallback error when response has no detail', async () => {
      mockPOST.mockResolvedValue({
        data: undefined,
        error: { status: 500 },
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
