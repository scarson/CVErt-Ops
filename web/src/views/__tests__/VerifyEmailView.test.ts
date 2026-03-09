// ABOUTME: Tests for the email verification page view.
// ABOUTME: Covers auto-verification on mount, success/error states, and missing token handling.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'

const mockRouteQuery = { token: undefined as string | undefined }

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ query: mockRouteQuery })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
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

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

async function mountVerifyEmail() {
  const { default: VerifyEmailView } = await import('@/views/VerifyEmailView.vue')
  return mount(VerifyEmailView)
}

describe('VerifyEmailView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()
    mockRouteQuery.token = 'valid-verification-token-hex'
  })

  describe('rendering', () => {
    it('renders heading', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'verifyEmail').mockResolvedValue({ success: true })

      const wrapper = await mountVerifyEmail()

      expect(wrapper.text()).toContain('Email Verification')
    })
  })

  describe('auto-verification on mount', () => {
    it('calls verifyEmail with token from URL on mount', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'verifyEmail').mockResolvedValue({ success: true })

      await mountVerifyEmail()
      await flushPromises()

      expect(auth.verifyEmail).toHaveBeenCalledWith('valid-verification-token-hex')
    })

    it('shows success message on successful verification', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'verifyEmail').mockResolvedValue({ success: true })

      const wrapper = await mountVerifyEmail()
      await flushPromises()

      expect(wrapper.text()).toContain('Your email has been verified successfully')
    })

    it('shows login link after successful verification', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'verifyEmail').mockResolvedValue({ success: true })

      const wrapper = await mountVerifyEmail()
      await flushPromises()

      const loginLink = wrapper.find('a[href="/login"]')
      expect(loginLink.exists()).toBe(true)
    })

    it('shows error message on failed verification', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'verifyEmail').mockResolvedValue({ success: false, error: 'Token expired' })

      const wrapper = await mountVerifyEmail()
      await flushPromises()

      expect(wrapper.text()).toContain('Token expired')
    })

    it('displays error with role="alert"', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'verifyEmail').mockResolvedValue({ success: false, error: 'Invalid token' })

      const wrapper = await mountVerifyEmail()
      await flushPromises()

      const errorEl = wrapper.find('[role="alert"]')
      expect(errorEl.exists()).toBe(true)
      expect(errorEl.text()).toContain('Invalid token')
    })

    it('shows helpful expired link text on error', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'verifyEmail').mockResolvedValue({ success: false, error: 'Verification failed' })

      const wrapper = await mountVerifyEmail()
      await flushPromises()

      expect(wrapper.text()).toContain('verification link may have expired')
    })
  })

  describe('missing token', () => {
    it('shows error when no token in URL', async () => {
      mockRouteQuery.token = undefined
      const auth = useAuthStore()
      vi.spyOn(auth, 'verifyEmail')

      const wrapper = await mountVerifyEmail()
      await flushPromises()

      expect(wrapper.text()).toContain('No verification token found')
      expect(auth.verifyEmail).not.toHaveBeenCalled()
    })

    it('shows login link when no token', async () => {
      mockRouteQuery.token = undefined

      const wrapper = await mountVerifyEmail()
      await flushPromises()

      const loginLink = wrapper.find('a[href="/login"]')
      expect(loginLink.exists()).toBe(true)
    })
  })
})
