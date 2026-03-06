// ABOUTME: Tests for the login page view.
// ABOUTME: Covers form rendering, validation, auth store integration, OAuth buttons, and redirect behavior.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { nextTick } from 'vue'

const mockPush = vi.fn()
const mockRouteQuery = { redirect: undefined as string | undefined }

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ query: mockRouteQuery })),
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

async function mountLogin() {
  const { default: LoginView } = await import('@/views/LoginView.vue')
  return mount(LoginView)
}

describe('LoginView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()
    mockRouteQuery.redirect = undefined
  })

  describe('rendering', () => {
    it('renders email and password inputs', async () => {
      const wrapper = await mountLogin()

      const emailInput = wrapper.find('input[type="email"]')
      const passwordInput = wrapper.find('input[type="password"]')
      expect(emailInput.exists()).toBe(true)
      expect(passwordInput.exists()).toBe(true)
    })

    it('renders labels for email and password', async () => {
      const wrapper = await mountLogin()

      const text = wrapper.text()
      expect(text).toContain('Email')
      expect(text).toContain('Password')
    })

    it('renders login button', async () => {
      const wrapper = await mountLogin()

      const button = wrapper.find('button[type="submit"]')
      expect(button.exists()).toBe(true)
      expect(button.text()).toContain('Log in')
    })

    it('renders OAuth buttons for GitHub and Google', async () => {
      const wrapper = await mountLogin()

      const buttons = wrapper.findAll('button')
      const buttonTexts = buttons.map((b) => b.text())
      expect(buttonTexts.some((t) => t.includes('GitHub'))).toBe(true)
      expect(buttonTexts.some((t) => t.includes('Google'))).toBe(true)
    })

    it('renders divider with "or continue with" text', async () => {
      const wrapper = await mountLogin()

      expect(wrapper.text()).toContain('or continue with')
    })

    it('renders register link pointing to /register', async () => {
      const wrapper = await mountLogin()

      const registerLink = wrapper.find('a[href="/register"]')
      expect(registerLink.exists()).toBe(true)
      expect(wrapper.text()).toContain('Register')
    })
  })

  describe('form submission', () => {
    it('calls auth store login with email and password on submit', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'login').mockResolvedValue({ success: true })

      const wrapper = await mountLogin()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('input[type="password"]').setValue('secret123')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(auth.login).toHaveBeenCalledWith('user@example.com', 'secret123')
    })

    it('disables login button while submitting', async () => {
      const auth = useAuthStore()
      let resolveLogin: (value: { success: boolean }) => void
      vi.spyOn(auth, 'login').mockImplementation(
        () => new Promise((resolve) => { resolveLogin = resolve }),
      )

      const wrapper = await mountLogin()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('input[type="password"]').setValue('secret123')
      await wrapper.find('form').trigger('submit')
      await nextTick()

      const submitButton = wrapper.find('button[type="submit"]')
      expect(submitButton.attributes('disabled')).toBeDefined()

      resolveLogin!({ success: true })
      await flushPromises()

      expect(submitButton.attributes('disabled')).toBeUndefined()
    })

    it('shows error message on failed login', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'login').mockResolvedValue({
        success: false,
        error: 'Invalid email or password',
      })

      const wrapper = await mountLogin()

      await wrapper.find('input[type="email"]').setValue('bad@example.com')
      await wrapper.find('input[type="password"]').setValue('wrong')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('Invalid email or password')
    })

    it('navigates to /cves after successful login (no redirect param)', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'login').mockResolvedValue({ success: true })

      const wrapper = await mountLogin()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('input[type="password"]').setValue('secret123')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(mockPush).toHaveBeenCalledWith('/cves')
    })

    it('navigates to redirect URL after successful login', async () => {
      mockRouteQuery.redirect = '/watchlists'

      const auth = useAuthStore()
      vi.spyOn(auth, 'login').mockResolvedValue({ success: true })

      const wrapper = await mountLogin()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('input[type="password"]').setValue('secret123')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(mockPush).toHaveBeenCalledWith('/watchlists')
    })

    it('displays error message with role="alert" for screen readers', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'login').mockResolvedValue({
        success: false,
        error: 'Invalid email or password',
      })

      const wrapper = await mountLogin()

      await wrapper.find('input[type="email"]').setValue('test@example.com')
      await wrapper.find('input[type="password"]').setValue('password')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      const errorEl = wrapper.find('.text-destructive')
      expect(errorEl.exists()).toBe(true)
      expect(errorEl.attributes('role')).toBe('alert')
    })

    it('associates error message with form via aria-describedby', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'login').mockResolvedValue({
        success: false,
        error: 'Invalid email or password',
      })

      const wrapper = await mountLogin()

      await wrapper.find('input[type="email"]').setValue('test@example.com')
      await wrapper.find('input[type="password"]').setValue('password')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      // Error element should have id and role="alert" (added in Task 4)
      const errorEl = wrapper.find('[role="alert"]')
      expect(errorEl.exists()).toBe(true)
      expect(errorEl.attributes('id')).toBe('login-error')

      // Form fields should reference the error
      const emailInput = wrapper.find('#email')
      expect(emailInput.attributes('aria-invalid')).toBe('true')
      expect(emailInput.attributes('aria-describedby')).toBe('login-error')
    })

    it('does not navigate on failed login', async () => {
      const auth = useAuthStore()
      vi.spyOn(auth, 'login').mockResolvedValue({
        success: false,
        error: 'Invalid email or password',
      })

      const wrapper = await mountLogin()

      await wrapper.find('input[type="email"]').setValue('bad@example.com')
      await wrapper.find('input[type="password"]').setValue('wrong')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(mockPush).not.toHaveBeenCalled()
    })
  })

  describe('OAuth buttons', () => {
    it('GitHub button redirects to OAuth endpoint', async () => {
      const originalLocation = window.location.href
      const hrefSetter = vi.fn()
      Object.defineProperty(window, 'location', {
        value: { ...window.location, get href() { return originalLocation }, set href(v: string) { hrefSetter(v) } },
        writable: true,
        configurable: true,
      })

      const wrapper = await mountLogin()

      const buttons = wrapper.findAll('button')
      const githubButton = buttons.find((b) => b.text().includes('GitHub'))!
      await githubButton.trigger('click')

      expect(hrefSetter).toHaveBeenCalledWith('/api/v1/auth/oauth/github')
    })

    it('Google button redirects to OAuth endpoint', async () => {
      const originalLocation = window.location.href
      const hrefSetter = vi.fn()
      Object.defineProperty(window, 'location', {
        value: { ...window.location, get href() { return originalLocation }, set href(v: string) { hrefSetter(v) } },
        writable: true,
        configurable: true,
      })

      const wrapper = await mountLogin()

      const buttons = wrapper.findAll('button')
      const googleButton = buttons.find((b) => b.text().includes('Google'))!
      await googleButton.trigger('click')

      expect(hrefSetter).toHaveBeenCalledWith('/api/v1/auth/oauth/google')
    })
  })
})
