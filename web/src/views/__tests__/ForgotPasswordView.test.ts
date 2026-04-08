// ABOUTME: Tests for the forgot password page view.
// ABOUTME: Covers form rendering, anti-enumeration (always shows success), and auth store integration.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { nextTick } from 'vue'

vi.mock('vue-router', () => ({
  useRoute: vi.fn<() => { query: Record<string, unknown> }>(() => ({ query: {} })),
  useRouter: vi.fn<() => { push: (...args: unknown[]) => unknown }>(() => ({
    push: vi.fn<(...args: unknown[]) => unknown>(),
  })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn<(...args: unknown[]) => unknown>(),
    POST: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

import { useAuthStore } from '@/stores/auth'

const mockFetch = vi.fn<(...args: unknown[]) => unknown>()
vi.stubGlobal('fetch', mockFetch)

async function mountForgotPassword() {
  const { default: ForgotPasswordView } = await import('@/views/ForgotPasswordView.vue')
  return mount(ForgotPasswordView)
}

describe('ForgotPasswordView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()
  })

  describe('rendering', () => {
    it('renders email input', async () => {
      const wrapper = await mountForgotPassword()
      const emailInput = wrapper.find('input[type="email"]')
      expect(emailInput.exists()).toBe(true)
    })

    it('renders submit button with correct text', async () => {
      const wrapper = await mountForgotPassword()
      const button = wrapper.find('button[type="submit"]')
      expect(button.exists()).toBe(true)
      expect(button.text()).toContain('Send reset link')
    })

    it('renders heading text', async () => {
      const wrapper = await mountForgotPassword()
      expect(wrapper.text()).toContain('Forgot your password?')
    })

    it('renders back to login link', async () => {
      const wrapper = await mountForgotPassword()
      const loginLink = wrapper.find('a[href="/login"]')
      expect(loginLink.exists()).toBe(true)
      expect(wrapper.text()).toContain('Back to login')
    })
  })

  describe('form submission', () => {
    it('calls auth store forgotPassword on submit', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'forgotPassword').mockResolvedValue({ success: true })

      const wrapper = await mountForgotPassword()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(auth.forgotPassword).toHaveBeenCalledWith('user@example.com')
    })

    it('shows success message after successful submit', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'forgotPassword').mockResolvedValue({ success: true })

      const wrapper = await mountForgotPassword()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('If an account with that email exists')
    })

    it('shows success message even on failure (anti-enumeration)', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'forgotPassword').mockResolvedValue({
        success: false,
        error: 'something went wrong',
      })

      const wrapper = await mountForgotPassword()

      await wrapper.find('input[type="email"]').setValue('nobody@example.com')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      // Anti-enumeration: same success message regardless of result.
      expect(wrapper.text()).toContain('If an account with that email exists')
    })

    it('hides the form after submission', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'forgotPassword').mockResolvedValue({ success: true })

      const wrapper = await mountForgotPassword()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.find('form').exists()).toBe(false)
    })

    it('disables button while submitting', async () => {
      const auth = useAuthStore()
      let resolveForgot: (value: { success: boolean }) => void
      vi.spyOn(auth, 'forgotPassword').mockImplementation(
        () =>
          new Promise((resolve) => {
            resolveForgot = resolve
          }),
      )

      const wrapper = await mountForgotPassword()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('form').trigger('submit')
      await nextTick()

      const submitButton = wrapper.find('button[type="submit"]')
      expect(submitButton.attributes('disabled')).toBeDefined()
      expect(submitButton.text()).toContain('Sending...')

      resolveForgot!({ success: true })
      await flushPromises()
    })
  })
})
