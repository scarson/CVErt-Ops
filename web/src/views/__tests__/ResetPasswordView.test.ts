// ABOUTME: Tests for the reset password page view.
// ABOUTME: Covers form rendering, client-side validation, success/error states, and missing token.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { nextTick } from 'vue'

const mockPush = vi.fn<(...args: unknown[]) => unknown>()
const mockRouteQuery = { token: undefined as string | undefined }

vi.mock('vue-router', () => ({
  useRoute: vi.fn<() => { query: typeof mockRouteQuery }>(() => ({ query: mockRouteQuery })),
  useRouter: vi.fn<() => { push: typeof mockPush }>(() => ({ push: mockPush })),
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

async function mountResetPassword() {
  const { default: ResetPasswordView } = await import('@/views/ResetPasswordView.vue')
  return mount(ResetPasswordView)
}

describe('ResetPasswordView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()
    vi.useFakeTimers()
    mockRouteQuery.token = 'valid-hex-token-abc123'
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('rendering', () => {
    it('renders password and confirm password inputs when token present', async () => {
      const wrapper = await mountResetPassword()
      expect(wrapper.find('#password').exists()).toBe(true)
      expect(wrapper.find('#confirm-password').exists()).toBe(true)
    })

    it('renders submit button', async () => {
      const wrapper = await mountResetPassword()
      const button = wrapper.find('button[type="submit"]')
      expect(button.exists()).toBe(true)
      expect(button.text()).toContain('Reset password')
    })

    it('renders heading', async () => {
      const wrapper = await mountResetPassword()
      expect(wrapper.text()).toContain('Reset your password')
    })
  })

  describe('missing token', () => {
    it('shows error when no token in URL', async () => {
      mockRouteQuery.token = undefined

      const wrapper = await mountResetPassword()

      expect(wrapper.text()).toContain('No reset token found')
      expect(wrapper.find('form').exists()).toBe(false)
    })

    it('shows link to forgot-password when no token', async () => {
      mockRouteQuery.token = undefined

      const wrapper = await mountResetPassword()

      const link = wrapper.find('a[href="/forgot-password"]')
      expect(link.exists()).toBe(true)
    })
  })

  describe('client-side validation', () => {
    it('shows error when passwords do not match', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'resetPassword')

      const wrapper = await mountResetPassword()

      await wrapper.find('#password').setValue('new-password-1234567')
      await wrapper.find('#confirm-password').setValue('different-password-1')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('Passwords do not match')
      expect(auth.resetPassword).not.toHaveBeenCalled()
    })
  })

  describe('form submission', () => {
    it('calls auth store resetPassword with token and password', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'resetPassword').mockResolvedValue({ success: true })

      const wrapper = await mountResetPassword()

      await wrapper.find('#password').setValue('new-password-1234567')
      await wrapper.find('#confirm-password').setValue('new-password-1234567')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(auth.resetPassword).toHaveBeenCalledWith(
        'valid-hex-token-abc123',
        'new-password-1234567',
      )
    })

    it('shows success message after successful reset', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'resetPassword').mockResolvedValue({ success: true })

      const wrapper = await mountResetPassword()

      await wrapper.find('#password').setValue('new-password-1234567')
      await wrapper.find('#confirm-password').setValue('new-password-1234567')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('Your password has been reset successfully')
    })

    it('redirects to /login after 3 seconds on success', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'resetPassword').mockResolvedValue({ success: true })

      const wrapper = await mountResetPassword()

      await wrapper.find('#password').setValue('new-password-1234567')
      await wrapper.find('#confirm-password').setValue('new-password-1234567')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(mockPush).not.toHaveBeenCalled()

      vi.advanceTimersByTime(3000)

      expect(mockPush).toHaveBeenCalledWith('/login')
    })

    it('shows error message on failure', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'resetPassword').mockResolvedValue({ success: false, error: 'Token expired' })

      const wrapper = await mountResetPassword()

      await wrapper.find('#password').setValue('new-password-1234567')
      await wrapper.find('#confirm-password').setValue('new-password-1234567')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('Token expired')
    })

    it('displays error with role="alert"', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'resetPassword').mockResolvedValue({ success: false, error: 'Invalid token' })

      const wrapper = await mountResetPassword()

      await wrapper.find('#password').setValue('new-password-1234567')
      await wrapper.find('#confirm-password').setValue('new-password-1234567')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      const errorEl = wrapper.find('[role="alert"]')
      expect(errorEl.exists()).toBe(true)
      expect(errorEl.text()).toContain('Invalid token')
    })

    it('disables button while submitting', async () => {
      const auth = useAuthStore()
      let resolveReset: (value: { success: boolean }) => void
      vi.spyOn(auth, 'resetPassword').mockImplementation(
        () =>
          new Promise((resolve) => {
            resolveReset = resolve
          }),
      )

      const wrapper = await mountResetPassword()

      await wrapper.find('#password').setValue('new-password-1234567')
      await wrapper.find('#confirm-password').setValue('new-password-1234567')
      await wrapper.find('form').trigger('submit')
      await nextTick()

      const submitButton = wrapper.find('button[type="submit"]')
      expect(submitButton.attributes('disabled')).toBeDefined()
      expect(submitButton.text()).toContain('Resetting...')

      resolveReset!({ success: true })
      await flushPromises()
    })
  })
})
