// ABOUTME: Tests for the account settings page.
// ABOUTME: Verifies the password and two-factor sections and the forced-password-change mode.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn<(...args: unknown[]) => unknown>(),
    POST: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

const stubs = {
  ChangePasswordCard: { template: '<div data-testid="password-card" />' },
  MfaSettingsCard: { template: '<div data-testid="mfa-card" />' },
}

function signIn(forcePasswordReset: boolean) {
  useAuthStore().user = {
    user_id: 'u1',
    email: 'me@example.com',
    display_name: 'Me',
    is_site_admin: false,
    force_password_reset: forcePasswordReset,
    has_password: true,
    orgs: [],
  }
}

async function mountView() {
  const { default: AccountView } = await import('../AccountView.vue')
  return mount(AccountView, { global: { stubs } })
}

describe('AccountView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('shows the password and two-factor sections', async () => {
    signIn(false)
    const wrapper = await mountView()

    expect(wrapper.find('h1').text()).toBe('Account')
    expect(wrapper.find('[data-testid="password-card"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="mfa-card"]').exists()).toBe(true)
  })

  it('shows only the password change when a new password is required', async () => {
    signIn(true)
    const wrapper = await mountView()

    expect(wrapper.find('[role="alert"]').text()).toContain('must change your password')
    expect(wrapper.find('[data-testid="password-card"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="mfa-card"]').exists()).toBe(false)
  })
})
