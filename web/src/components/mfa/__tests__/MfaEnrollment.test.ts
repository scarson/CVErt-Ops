// ABOUTME: Tests for the MFA enrollment flow shared by sign-in and the account page.
// ABOUTME: Covers TOTP setup/QR/secret/confirm, email OTP setup/confirm, and every error type.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import {
  PROBLEM_ENROLLMENT_EXPIRED,
  PROBLEM_INVALID_CODE,
  PROBLEM_PENDING_SESSION_INVALID,
} from '@/lib/api/problems'

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn<(...args: unknown[]) => unknown>(),
    POST: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

import client from '@/lib/api/client'

const mockPOST = vi.mocked(client.POST)

const TOTP_SETUP = {
  qr_code_uri: 'otpauth://totp/CVErt%20Ops:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=CVErt%20Ops',
  secret: 'JBSWY3DPEHPK3PXP',
}

function ok(data: unknown) {
  return { data, error: undefined, response: { status: 200 } as Response } as any
}

function problem(status: number, type: string | undefined, detail: string) {
  return {
    data: undefined,
    error: { type: type ?? 'about:blank', status, detail },
    response: { status } as Response,
  } as any
}

async function mountEnrollment(enrolledMethods: string[] = []) {
  const { default: MfaEnrollment } = await import('../MfaEnrollment.vue')
  return mount(MfaEnrollment, { props: { enrolledMethods } })
}

async function startTotp(wrapper: Awaited<ReturnType<typeof mountEnrollment>>) {
  mockPOST.mockResolvedValueOnce(ok(TOTP_SETUP))
  await wrapper.find('[data-testid="enroll-totp"]').trigger('click')
  await flushPromises()
}

async function submitCode(wrapper: Awaited<ReturnType<typeof mountEnrollment>>, code: string) {
  await wrapper.find('input#enroll-code').setValue(code)
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

describe('MfaEnrollment', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.resetAllMocks()
  })

  it('offers only methods that are not enrolled yet', async () => {
    const wrapper = await mountEnrollment(['totp'])

    expect(wrapper.find('[data-testid="enroll-totp"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="enroll-email_otp"]').exists()).toBe(true)
  })

  describe('authenticator app', () => {
    it('shows a QR code image built from the setup URI and hides the secret until asked', async () => {
      const wrapper = await mountEnrollment()
      await startTotp(wrapper)

      expect(mockPOST).toHaveBeenCalledWith('/auth/mfa/totp/setup')
      const img = wrapper.find('img[data-testid="totp-qr"]')
      expect(img.attributes('src')).toMatch(/^data:image\/svg\+xml,/)
      expect(img.attributes('alt')).toContain('QR code')
      expect(wrapper.text()).not.toContain(TOTP_SETUP.secret)

      await wrapper.find('[data-testid="show-totp-secret"]').trigger('click')
      expect(wrapper.text()).toContain(TOTP_SETUP.secret)
    })

    it('confirms the code and emits the recovery codes', async () => {
      const wrapper = await mountEnrollment()
      await startTotp(wrapper)
      mockPOST.mockResolvedValueOnce(ok({ recovery_codes: ['abcde-12345'] }))

      await submitCode(wrapper, ' 123456 ')

      expect(mockPOST).toHaveBeenLastCalledWith('/auth/mfa/totp/confirm', { body: { code: '123456' } })
      expect(wrapper.emitted('enrolled')).toEqual([[['abcde-12345']]])
    })

    it('keeps the step on a wrong code', async () => {
      const wrapper = await mountEnrollment()
      await startTotp(wrapper)
      mockPOST.mockResolvedValueOnce(problem(401, PROBLEM_INVALID_CODE, 'invalid TOTP code'))

      await submitCode(wrapper, '000000')

      expect(wrapper.find('[role="alert"]').text()).toBe('That code is not correct. Try again.')
      expect(wrapper.emitted('enrolled')).toBeUndefined()
    })

    it('restarts setup with a new QR code when the enrollment expired', async () => {
      const wrapper = await mountEnrollment()
      await startTotp(wrapper)
      mockPOST.mockResolvedValueOnce(problem(401, PROBLEM_ENROLLMENT_EXPIRED, 'invalid or expired enrollment token'))
      mockPOST.mockResolvedValueOnce(ok({ ...TOTP_SETUP, secret: 'NEWSECRETNEWSECRET' }))

      await submitCode(wrapper, '123456')

      expect(mockPOST).toHaveBeenLastCalledWith('/auth/mfa/totp/setup')
      expect(wrapper.find('[role="alert"]').text()).toContain('previous QR code no longer works')
    })
  })

  describe('email code', () => {
    it('sends a code and confirms it', async () => {
      const wrapper = await mountEnrollment()
      mockPOST.mockResolvedValueOnce(ok(undefined))
      await wrapper.find('[data-testid="enroll-email_otp"]').trigger('click')
      await flushPromises()

      expect(mockPOST).toHaveBeenCalledWith('/auth/mfa/email-otp/setup')
      mockPOST.mockResolvedValueOnce(ok({}))
      await submitCode(wrapper, '654321')

      expect(mockPOST).toHaveBeenLastCalledWith('/auth/mfa/email-otp/confirm', { body: { code: '654321' } })
      expect(wrapper.emitted('enrolled')).toEqual([[[]]])
    })
  })

  it('emits session-expired when the sign-in session is no longer valid', async () => {
    const wrapper = await mountEnrollment()
    mockPOST.mockResolvedValueOnce(problem(401, PROBLEM_PENDING_SESSION_INVALID, 'invalid or expired pending token'))

    await wrapper.find('[data-testid="enroll-totp"]').trigger('click')
    await flushPromises()

    expect(wrapper.emitted('session-expired')).toHaveLength(1)
  })

  it('shows the server detail for other failures', async () => {
    const wrapper = await mountEnrollment()
    mockPOST.mockResolvedValueOnce(problem(409, undefined, 'totp already enrolled'))

    await wrapper.find('[data-testid="enroll-totp"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[role="alert"]').text()).toBe('totp already enrolled')
  })
})
