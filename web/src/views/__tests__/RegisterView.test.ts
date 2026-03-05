// ABOUTME: Tests for the registration page view.
// ABOUTME: Covers form rendering, client-side validation, API error handling, and auto-login after registration.

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

import client from '@/lib/api/client'
import { useAuthStore } from '@/stores/auth'

const mockClient = vi.mocked(client)

async function mountRegister() {
  const { default: RegisterView } = await import('@/views/RegisterView.vue')
  return mount(RegisterView)
}

describe('RegisterView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()
  })

  describe('rendering', () => {
    it('renders email input', async () => {
      const wrapper = await mountRegister()
      const emailInput = wrapper.find('input[type="email"]')
      expect(emailInput.exists()).toBe(true)
    })

    it('renders password input', async () => {
      const wrapper = await mountRegister()
      const passwordInput = wrapper.find('#password')
      expect(passwordInput.exists()).toBe(true)
      expect(passwordInput.attributes('type')).toBe('password')
    })

    it('renders confirm password input', async () => {
      const wrapper = await mountRegister()
      const confirmInput = wrapper.find('#confirm-password')
      expect(confirmInput.exists()).toBe(true)
      expect(confirmInput.attributes('type')).toBe('password')
    })

    it('renders display name input', async () => {
      const wrapper = await mountRegister()
      const displayNameInput = wrapper.find('#display-name')
      expect(displayNameInput.exists()).toBe(true)
    })

    it('renders register button', async () => {
      const wrapper = await mountRegister()
      const button = wrapper.find('button[type="submit"]')
      expect(button.exists()).toBe(true)
      expect(button.text()).toContain('Register')
    })

    it('renders OAuth buttons for GitHub and Google', async () => {
      const wrapper = await mountRegister()
      const buttons = wrapper.findAll('button')
      const buttonTexts = buttons.map((b) => b.text())
      expect(buttonTexts.some((t) => t.includes('GitHub'))).toBe(true)
      expect(buttonTexts.some((t) => t.includes('Google'))).toBe(true)
    })

    it('renders login link pointing to /login', async () => {
      const wrapper = await mountRegister()
      const loginLink = wrapper.find('a[href="/login"]')
      expect(loginLink.exists()).toBe(true)
      expect(wrapper.text()).toContain('Log in')
    })

    it('shows password hint about minimum length', async () => {
      const wrapper = await mountRegister()
      expect(wrapper.text()).toContain('16+ characters')
    })
  })

  describe('client-side validation', () => {
    it('shows error when passwords do not match', async () => {
      const wrapper = await mountRegister()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('#password').setValue('abcdefghijklmnop')
      await wrapper.find('#confirm-password').setValue('different-password')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('Passwords do not match')
      // Should not call the API
      expect(mockClient.POST).not.toHaveBeenCalled()
    })
  })

  describe('form submission', () => {
    it('calls API POST /auth/register on submit', async () => {
      vi.mocked(mockClient.POST).mockResolvedValue({
        data: { user_id: 'u1' },
        error: undefined,
        response: new Response(),
      } as any)

      const auth = useAuthStore()
      vi.spyOn(auth, 'login').mockResolvedValue({ success: true })

      const wrapper = await mountRegister()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('#password').setValue('abcdefghijklmnop')
      await wrapper.find('#confirm-password').setValue('abcdefghijklmnop')
      await wrapper.find('#display-name').setValue('Test User')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(mockClient.POST).toHaveBeenCalledWith('/auth/register', {
        body: {
          email: 'user@example.com',
          password: 'abcdefghijklmnop',
          display_name: 'Test User',
        },
      })
    })

    it('omits display_name when not provided', async () => {
      vi.mocked(mockClient.POST).mockResolvedValue({
        data: { user_id: 'u1' },
        error: undefined,
        response: new Response(),
      } as any)

      const auth = useAuthStore()
      vi.spyOn(auth, 'login').mockResolvedValue({ success: true })

      const wrapper = await mountRegister()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('#password').setValue('abcdefghijklmnop')
      await wrapper.find('#confirm-password').setValue('abcdefghijklmnop')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(mockClient.POST).toHaveBeenCalledWith('/auth/register', {
        body: {
          email: 'user@example.com',
          password: 'abcdefghijklmnop',
        },
      })
    })

    it('auto-logs in after successful registration', async () => {
      vi.mocked(mockClient.POST).mockResolvedValue({
        data: { user_id: 'u1' },
        error: undefined,
        response: new Response(),
      } as any)

      const auth = useAuthStore()
      vi.spyOn(auth, 'login').mockResolvedValue({ success: true })

      const wrapper = await mountRegister()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('#password').setValue('abcdefghijklmnop')
      await wrapper.find('#confirm-password').setValue('abcdefghijklmnop')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(auth.login).toHaveBeenCalledWith('user@example.com', 'abcdefghijklmnop')
    })

    it('disables register button while submitting', async () => {
      let resolvePost: (value: unknown) => void
      vi.mocked(mockClient.POST).mockImplementation(
        () => new Promise((resolve) => { resolvePost = resolve }) as any,
      )

      const wrapper = await mountRegister()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('#password').setValue('abcdefghijklmnop')
      await wrapper.find('#confirm-password').setValue('abcdefghijklmnop')
      await wrapper.find('form').trigger('submit')
      await nextTick()

      const submitButton = wrapper.find('button[type="submit"]')
      expect(submitButton.attributes('disabled')).toBeDefined()

      resolvePost!({ data: { user_id: 'u1' }, error: undefined, response: new Response() })
      await flushPromises()
    })
  })

  describe('error handling', () => {
    it('shows error on 409 (email already registered)', async () => {
      vi.mocked(mockClient.POST).mockResolvedValue({
        data: undefined,
        error: { status: 409, detail: 'Email already taken' },
        response: { status: 409 },
      } as any)

      const wrapper = await mountRegister()

      await wrapper.find('input[type="email"]').setValue('taken@example.com')
      await wrapper.find('#password').setValue('abcdefghijklmnop')
      await wrapper.find('#confirm-password').setValue('abcdefghijklmnop')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('Email already registered')
    })

    it('shows error on 403 (invite-only mode)', async () => {
      vi.mocked(mockClient.POST).mockResolvedValue({
        data: undefined,
        error: { status: 403, detail: 'Registration disabled' },
        response: { status: 403 },
      } as any)

      const wrapper = await mountRegister()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('#password').setValue('abcdefghijklmnop')
      await wrapper.find('#confirm-password').setValue('abcdefghijklmnop')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('Registration is invite-only')
    })

    it('shows generic error for other failures', async () => {
      vi.mocked(mockClient.POST).mockResolvedValue({
        data: undefined,
        error: { status: 500, detail: 'Internal server error' },
        response: { status: 500 },
      } as any)

      const wrapper = await mountRegister()

      await wrapper.find('input[type="email"]').setValue('user@example.com')
      await wrapper.find('#password').setValue('abcdefghijklmnop')
      await wrapper.find('#confirm-password').setValue('abcdefghijklmnop')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.text()).toContain('Registration failed')
    })
  })
})
