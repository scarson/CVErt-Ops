// ABOUTME: Tests for the account page's change-password card.
// ABOUTME: Covers validation, the wrong-current-password error, sign-out after success, and OAuth-only accounts.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { PROBLEM_INVALID_PASSWORD } from '@/lib/api/problems'

const mockPush = vi.fn<(...args: unknown[]) => unknown>()
vi.mock('vue-router', () => ({
  useRouter: vi.fn<() => unknown>(() => ({ push: mockPush })),
}))

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn<(...args: unknown[]) => unknown>(),
    POST: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

import client from '@/lib/api/client'

const mockPOST = vi.mocked(client.POST)

function signIn(hasPassword = true) {
  const auth = useAuthStore()
  auth.user = {
    user_id: 'u1',
    email: 'me@example.com',
    display_name: 'Me',
    is_site_admin: false,
    force_password_reset: false,
    has_password: hasPassword,
    orgs: [],
  }
  return auth
}

async function mountCard() {
  const { default: ChangePasswordCard } = await import('../ChangePasswordCard.vue')
  return mount(ChangePasswordCard)
}

async function submit(wrapper: Awaited<ReturnType<typeof mountCard>>, current: string, next: string, confirm = next) {
  await wrapper.find('input#current-password').setValue(current)
  await wrapper.find('input#account-new-password').setValue(next)
  await wrapper.find('input#account-confirm-password').setValue(confirm)
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

describe('ChangePasswordCard', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.resetAllMocks()
  })

  it('validates the new password before sending', async () => {
    signIn()
    const wrapper = await mountCard()

    await submit(wrapper, 'old-password-123456', 'short')

    expect(mockPOST).not.toHaveBeenCalled()
    expect(wrapper.find('[role="alert"]').text()).toContain('at least 16 characters')
  })

  it('reports a wrong current password', async () => {
    signIn()
    mockPOST.mockResolvedValueOnce({
      data: undefined,
      error: { type: PROBLEM_INVALID_PASSWORD, status: 401, detail: 'current password incorrect' },
      response: { status: 401 } as Response,
    } as any)
    const wrapper = await mountCard()

    await submit(wrapper, 'wrong-password-12345', 'a-long-new-password-1')

    expect(wrapper.find('[role="alert"]').text()).toBe('Your current password is not correct.')
  })

  it('changes the password, signs out, and asks the user to sign in again', async () => {
    const auth = signIn()
    mockPOST.mockResolvedValue({ data: {}, error: undefined, response: { status: 200 } as Response } as any)
    const wrapper = await mountCard()

    await submit(wrapper, 'old-password-123456', 'a-long-new-password-1')

    expect(mockPOST).toHaveBeenCalledWith('/auth/change-password', {
      body: { current_password: 'old-password-123456', new_password: 'a-long-new-password-1' },
    })
    expect(mockPOST).toHaveBeenCalledWith('/auth/logout')
    expect(auth.isAuthenticated).toBe(false)
    expect(auth.signInNotice).toBe('Password changed. Sign in again.')
    expect(mockPush).toHaveBeenCalledWith({ name: 'login' })
  })

  it('explains that an external-provider account has no password here', async () => {
    signIn(false)
    const wrapper = await mountCard()

    expect(wrapper.find('form').exists()).toBe(false)
    expect(wrapper.text()).toContain('external identity provider')
  })
})
