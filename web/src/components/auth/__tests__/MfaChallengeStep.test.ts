// ABOUTME: Tests for the MFA challenge step shown during sign-in.
// ABOUTME: Covers TOTP, email OTP send/resend, recovery codes, remember-device, errors, and cancel.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { PROBLEM_INVALID_CODE } from '@/lib/api/problems'
import MfaChallengeStep from '../MfaChallengeStep.vue'

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn<(...args: unknown[]) => unknown>(),
    POST: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

async function mountStep(pending: string[], methods: string[]) {
  const auth = useAuthStore()
  auth.pendingSteps = pending
  auth.mfaMethods = methods
  auth.signInEmail = 'mfa@example.com'
  const startSpy = vi.spyOn(auth, 'startMfaChallenge').mockResolvedValue({ ok: true })
  const verifySpy = vi.spyOn(auth, 'verifyMfa').mockResolvedValue({ ok: true, complete: true })
  const cancelSpy = vi.spyOn(auth, 'cancelSignIn').mockResolvedValue()
  const wrapper = mount(MfaChallengeStep, { attachTo: document.body })
  await flushPromises()
  return { wrapper, auth, startSpy, verifySpy, cancelSpy }
}

describe('MfaChallengeStep', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    document.body.innerHTML = ''
  })

  describe('authenticator app', () => {
    it('renews the sign-in session and shows a one-time-code input', async () => {
      const { wrapper, startSpy } = await mountStep(['mfa_challenge'], ['totp'])

      expect(startSpy).toHaveBeenCalledWith('totp')
      const input = wrapper.find('input#mfa-code')
      expect(input.attributes('autocomplete')).toBe('one-time-code')
      expect(input.attributes('inputmode')).toBe('numeric')
    })

    it('verifies the code and emits complete when sign-in finishes', async () => {
      const { wrapper, verifySpy } = await mountStep(['mfa_challenge'], ['totp'])

      await wrapper.find('input#mfa-code').setValue(' 123456 ')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(verifySpy).toHaveBeenCalledWith('totp', '123456', false)
      expect(wrapper.emitted('complete')).toHaveLength(1)
    })

    it('does not emit complete when more steps remain', async () => {
      const { wrapper, verifySpy } = await mountStep(['mfa_challenge', 'password_reset'], ['totp'])
      verifySpy.mockResolvedValueOnce({ ok: true, complete: false })

      await wrapper.find('input#mfa-code').setValue('123456')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(wrapper.emitted('complete')).toBeUndefined()
    })

    it('shows the error and keeps the step on a wrong code', async () => {
      const { wrapper, verifySpy } = await mountStep(['mfa_challenge'], ['totp'])
      verifySpy.mockResolvedValueOnce({
        ok: false,
        problemType: PROBLEM_INVALID_CODE,
        error: 'That code is not correct. Try again.',
      })

      await wrapper.find('input#mfa-code').setValue('000000')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      const alert = wrapper.find('[role="alert"]')
      expect(alert.text()).toBe('That code is not correct. Try again.')
      expect(wrapper.find('input#mfa-code').exists()).toBe(true)
    })
  })

  describe('remember device', () => {
    it('is offered when the MFA check is the last step and is passed to verify', async () => {
      const { wrapper, verifySpy } = await mountStep(['mfa_challenge'], ['totp'])

      const checkbox = wrapper.find('input#remember-device')
      expect(checkbox.exists()).toBe(true)
      await checkbox.setValue(true)
      await wrapper.find('input#mfa-code').setValue('123456')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(verifySpy).toHaveBeenCalledWith('totp', '123456', true)
    })

    it('is not offered when other steps follow', async () => {
      const { wrapper } = await mountStep(['mfa_challenge', 'password_reset'], ['totp'])

      expect(wrapper.find('input#remember-device').exists()).toBe(false)
    })
  })

  describe('email code', () => {
    it('sends a code on request and offers a resend', async () => {
      const { wrapper, startSpy } = await mountStep(['mfa_challenge'], ['email_otp'])

      expect(startSpy).not.toHaveBeenCalled()
      await wrapper.find('[data-testid="send-email-code"]').trigger('click')
      await flushPromises()

      expect(startSpy).toHaveBeenCalledWith('email_otp')
      expect(wrapper.text()).toContain('Only the most recent code works')
      expect(wrapper.find('[data-testid="send-email-code"]').text()).toContain('Resend code')
    })

    it('shows the rate-limit message when sending fails', async () => {
      const { wrapper, startSpy } = await mountStep(['mfa_challenge'], ['email_otp'])
      startSpy.mockResolvedValueOnce({ ok: false, error: 'too many email OTP requests — try again later' })

      await wrapper.find('[data-testid="send-email-code"]').trigger('click')
      await flushPromises()

      expect(wrapper.find('[role="alert"]').text()).toBe('too many email OTP requests — try again later')
    })

    it('asks for a new code after three wrong email codes', async () => {
      const { wrapper, verifySpy } = await mountStep(['mfa_challenge'], ['email_otp'])
      verifySpy.mockResolvedValue({
        ok: false,
        problemType: PROBLEM_INVALID_CODE,
        error: 'That code is not correct. Try again.',
      })
      await wrapper.find('[data-testid="send-email-code"]').trigger('click')
      await flushPromises()

      for (let i = 0; i < 3; i++) {
        await wrapper.find('input#mfa-code').setValue('000000')
        await wrapper.find('form').trigger('submit')
        await flushPromises()
      }

      expect(wrapper.find('[role="alert"]').text()).toContain('Request a new code')
    })
  })

  describe('method choice', () => {
    it('lets the user switch methods only when both are enrolled', async () => {
      const both = await mountStep(['mfa_challenge'], ['totp', 'email_otp'])
      expect(both.wrapper.find('[data-testid="method-email_otp"]').exists()).toBe(true)
      await both.wrapper.find('[data-testid="method-email_otp"]').trigger('click')
      expect(both.wrapper.find('[data-testid="send-email-code"]').exists()).toBe(true)
      both.wrapper.unmount()

      setActivePinia(createPinia())
      const single = await mountStep(['mfa_challenge'], ['totp'])
      expect(single.wrapper.find('[data-testid="method-email_otp"]').exists()).toBe(false)
    })
  })

  describe('recovery code', () => {
    it('verifies a trimmed recovery code', async () => {
      const { wrapper, verifySpy } = await mountStep(['mfa_challenge'], ['totp'])

      await wrapper.find('[data-testid="use-recovery-code"]').trigger('click')
      const input = wrapper.find('input#mfa-code')
      expect(input.attributes('inputmode')).toBe('text')
      await input.setValue('  abcde-12345 ')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(verifySpy).toHaveBeenCalledWith('recovery', 'abcde-12345', false)
    })
  })

  it('cancels the sign-in', async () => {
    const { wrapper, cancelSpy } = await mountStep(['mfa_challenge'], ['totp'])

    await wrapper.find('[data-testid="cancel-sign-in"]').trigger('click')

    expect(cancelSpy).toHaveBeenCalled()
  })

  it('moves focus to the step heading', async () => {
    await mountStep(['mfa_challenge'], ['totp'])

    expect(document.activeElement?.tagName).toBe('H2')
  })
})
