// ABOUTME: Tests for the account page's two-factor authentication card.
// ABOUTME: Covers listing methods and requirements, adding, removing, regenerating codes, and OAuth-only accounts.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { defineComponent, h } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { PROBLEM_INVALID_PASSWORD } from '@/lib/api/problems'
import MfaSettingsCard from '../MfaSettingsCard.vue'

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn<(...args: unknown[]) => unknown>(),
    POST: vi.fn<(...args: unknown[]) => unknown>(),
    DELETE: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

import client from '@/lib/api/client'

const mockGET = vi.mocked(client.GET)
const mockPOST = vi.mocked(client.POST)
const mockDELETE = vi.mocked(client.DELETE)

const MfaEnrollmentStub = defineComponent({
  name: 'MfaEnrollment',
  props: { enrolledMethods: { type: Array, required: true } },
  emits: ['enrolled', 'session-expired'],
  setup() {
    return () => h('div', { 'data-testid': 'mfa-enrollment' })
  },
})

function methodsResponse(overrides: Record<string, unknown> = {}) {
  return {
    data: {
      methods: [{ method: 'totp', created_at: '2026-10-01T12:00:00Z' }],
      recovery_codes_remaining: 8,
      required: false,
      required_reasons: [],
      ...overrides,
    },
    error: undefined,
    response: { status: 200 } as Response,
  } as any
}

function signIn(hasPassword = true) {
  useAuthStore().user = {
    user_id: 'u1',
    email: 'me@example.com',
    display_name: 'Me',
    is_site_admin: false,
    force_password_reset: false,
    has_password: hasPassword,
    orgs: [],
  }
}

async function mountCard() {
  const wrapper = mount(MfaSettingsCard, {
    attachTo: document.body,
    global: { stubs: { MfaEnrollment: MfaEnrollmentStub } },
  })
  await flushPromises()
  return wrapper
}

function bodyQuery(selector: string) {
  return document.body.querySelector(selector) as HTMLElement | null
}

// Dialog content is teleported to <body>, outside the wrapper.
async function confirmPassword(password: string) {
  const input = bodyQuery('#confirm-current-password') as HTMLInputElement
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(input, password)
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await flushPromises()
  bodyQuery('[data-testid="password-confirm-submit"]')!.click()
  await flushPromises()
}

describe('MfaSettingsCard', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.resetAllMocks()
    document.body.innerHTML = ''
    signIn()
  })

  it('lists enrolled methods and remaining recovery codes', async () => {
    mockGET.mockResolvedValueOnce(methodsResponse())
    const wrapper = await mountCard()

    expect(mockGET).toHaveBeenCalledWith('/auth/mfa/methods')
    expect(wrapper.text()).toContain('Authenticator app')
    expect(wrapper.text()).toContain('8 recovery codes left')
    expect(wrapper.find('[data-testid="recovery-codes-low"]').exists()).toBe(false)
  })

  it('warns when two or fewer recovery codes remain', async () => {
    mockGET.mockResolvedValueOnce(methodsResponse({ recovery_codes_remaining: 2 }))
    const wrapper = await mountCard()

    expect(wrapper.find('[data-testid="recovery-codes-low"]').exists()).toBe(true)
  })

  it('explains why MFA is required', async () => {
    mockGET.mockResolvedValueOnce(
      methodsResponse({
        required: true,
        required_reasons: [{ source: 'site_admin' }, { source: 'org_policy', org_name: 'Acme' }],
      }),
    )
    const wrapper = await mountCard()

    expect(wrapper.text()).toContain('Required because')
    expect(wrapper.text()).toContain('you are a site administrator')
    expect(wrapper.text()).toContain('Acme requires it for all members')
  })

  it('shows recovery codes after the first enrollment, then reloads the methods', async () => {
    mockGET.mockResolvedValueOnce(methodsResponse({ methods: [], recovery_codes_remaining: 0 }))
    mockGET.mockResolvedValueOnce(methodsResponse())
    const wrapper = await mountCard()

    await wrapper.find('[data-testid="add-mfa-method"]').trigger('click')
    expect(wrapper.findComponent(MfaEnrollmentStub).props('enrolledMethods')).toEqual([])
    wrapper.findComponent(MfaEnrollmentStub).vm.$emit('enrolled', ['abcde-12345'])
    await flushPromises()

    expect(wrapper.text()).toContain('abcde-12345')
    await wrapper.find('input#recovery-codes-saved').setValue(true)
    await wrapper.find('[data-testid="recovery-codes-done"]').trigger('click')
    await flushPromises()

    expect(mockGET).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).not.toContain('abcde-12345')
  })

  it('reloads without a code screen when adding a second method', async () => {
    mockGET.mockResolvedValue(methodsResponse())
    const wrapper = await mountCard()

    await wrapper.find('[data-testid="add-mfa-method"]').trigger('click')
    expect(wrapper.findComponent(MfaEnrollmentStub).props('enrolledMethods')).toEqual(['totp'])
    wrapper.findComponent(MfaEnrollmentStub).vm.$emit('enrolled', [])
    await flushPromises()

    expect(wrapper.find('[data-testid="recovery-codes-done"]').exists()).toBe(false)
    expect(mockGET).toHaveBeenCalledTimes(2)
  })

  it('removes a method after password confirmation', async () => {
    mockGET.mockResolvedValue(methodsResponse())
    mockDELETE.mockResolvedValueOnce({ data: undefined, error: undefined, response: { status: 204 } as Response } as any)
    const wrapper = await mountCard()

    await wrapper.find('[data-testid="remove-totp"]').trigger('click')
    await flushPromises()
    await confirmPassword('my-password-123456')

    expect(mockDELETE).toHaveBeenCalledWith('/auth/mfa/methods/{method}', {
      params: { path: { method: 'totp' } },
      body: { current_password: 'my-password-123456' },
    })
    expect(mockGET).toHaveBeenCalledTimes(2)
  })

  it('shows the server reason when a required method cannot be removed', async () => {
    mockGET.mockResolvedValue(methodsResponse())
    mockDELETE.mockResolvedValueOnce({
      data: undefined,
      error: { status: 403, detail: 'MFA is required and cannot be disabled' },
      response: { status: 403 } as Response,
    } as any)
    const wrapper = await mountCard()

    await wrapper.find('[data-testid="remove-totp"]').trigger('click')
    await flushPromises()
    await confirmPassword('my-password-123456')

    expect(bodyQuery('#password-confirm-error')?.textContent?.trim()).toBe('MFA is required and cannot be disabled')
  })

  it('regenerates recovery codes after password confirmation', async () => {
    mockGET.mockResolvedValue(methodsResponse())
    mockPOST.mockResolvedValueOnce({
      data: { recovery_codes: ['zzzzz-99999'] },
      error: undefined,
      response: { status: 200 } as Response,
    } as any)
    const wrapper = await mountCard()

    await wrapper.find('[data-testid="regenerate-recovery-codes"]').trigger('click')
    await flushPromises()
    await confirmPassword('my-password-123456')

    expect(mockPOST).toHaveBeenCalledWith('/auth/mfa/recovery-codes/regenerate', {
      body: { current_password: 'my-password-123456' },
    })
    expect(wrapper.text()).toContain('zzzzz-99999')
  })

  it('reports a wrong password in the dialog', async () => {
    mockGET.mockResolvedValue(methodsResponse())
    mockPOST.mockResolvedValueOnce({
      data: undefined,
      error: { type: PROBLEM_INVALID_PASSWORD, status: 401, detail: 'current password incorrect' },
      response: { status: 401 } as Response,
    } as any)
    const wrapper = await mountCard()

    await wrapper.find('[data-testid="regenerate-recovery-codes"]').trigger('click')
    await flushPromises()
    await confirmPassword('wrong-password-12345')

    expect(bodyQuery('#password-confirm-error')?.textContent?.trim()).toBe('Your password is not correct.')
  })

  it('replaces password-gated actions with an explanation for external-provider accounts', async () => {
    signIn(false)
    mockGET.mockResolvedValueOnce(methodsResponse())
    const wrapper = await mountCard()

    expect(wrapper.find('[data-testid="remove-totp"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="regenerate-recovery-codes"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('need a password')
  })

  it('shows an error when the methods cannot be loaded', async () => {
    mockGET.mockResolvedValueOnce({
      data: undefined,
      error: { status: 503, detail: 'Could not reach the server. Check your connection and try again.' },
      response: { status: 503 } as Response,
    } as any)
    const wrapper = await mountCard()

    expect(wrapper.find('[role="alert"]').text()).toContain('Could not reach the server')
  })
})
