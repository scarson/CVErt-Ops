// ABOUTME: Tests for the auth store's multi-step sign-in (pending steps after password login).
// ABOUTME: Covers MFA challenge and verify, forced password change, completion, expiry, and cancel.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAuthStore } from '../auth'
import {
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

const mockClient = vi.mocked(client)

const meData = {
  user_id: 'u1',
  email: 'mfa@example.com',
  display_name: 'MFA User',
  is_site_admin: false,
  force_password_reset: false,
  has_password: true,
  orgs: [],
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

async function signedInToPendingSteps(pending: string[], methods: string[] = []) {
  mockClient.POST.mockResolvedValueOnce(ok({ user_id: 'u1', pending, methods }))
  const auth = useAuthStore()
  await auth.login('mfa@example.com', 'password-123456789')
  return auth
}

describe('auth store sign-in steps', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.resetAllMocks()
  })

  describe('login', () => {
    it('keeps the pending steps and methods instead of fetching the user', async () => {
      const auth = await signedInToPendingSteps(['mfa_challenge', 'password_reset'], ['totp', 'email_otp'])

      expect(auth.pendingSteps).toEqual(['mfa_challenge', 'password_reset'])
      expect(auth.mfaMethods).toEqual(['totp', 'email_otp'])
      expect(auth.signInEmail).toBe('mfa@example.com')
      expect(auth.isAuthenticated).toBe(false)
      expect(mockClient.GET).not.toHaveBeenCalled()
    })

    it('reports a pending sign-in as not yet successful and without an error', async () => {
      mockClient.POST.mockResolvedValueOnce(ok({ user_id: 'u1', pending: ['mfa_challenge'], methods: ['totp'] }))
      const auth = useAuthStore()

      const result = await auth.login('mfa@example.com', 'password-123456789')

      expect(result).toEqual({ success: false })
    })

    it('treats a null pending list as a completed sign-in', async () => {
      mockClient.POST.mockResolvedValueOnce(ok({ user_id: 'u1', pending: null }))
      mockClient.GET.mockResolvedValueOnce(ok(meData))
      const auth = useAuthStore()

      const result = await auth.login('mfa@example.com', 'password-123456789')

      expect(result.success).toBe(true)
      expect(auth.pendingSteps).toEqual([])
    })
  })

  describe('startMfaChallenge', () => {
    it('posts the chosen method', async () => {
      const auth = await signedInToPendingSteps(['mfa_challenge'], ['email_otp'])
      mockClient.POST.mockResolvedValueOnce(ok(undefined))

      const result = await auth.startMfaChallenge('email_otp')

      expect(result.ok).toBe(true)
      expect(mockClient.POST).toHaveBeenLastCalledWith('/auth/mfa/challenge', {
        body: { method: 'email_otp' },
      })
    })

    it('returns the server detail when email codes are rate limited', async () => {
      const auth = await signedInToPendingSteps(['mfa_challenge'], ['email_otp'])
      mockClient.POST.mockResolvedValueOnce(
        problem(429, undefined, 'too many email OTP requests — try again later'),
      )

      const result = await auth.startMfaChallenge('email_otp')

      expect(result.ok).toBe(false)
      expect(result.error).toBe('too many email OTP requests — try again later')
      expect(auth.pendingSteps).toEqual(['mfa_challenge'])
    })
  })

  describe('verifyMfa', () => {
    it('moves to the next pending step', async () => {
      const auth = await signedInToPendingSteps(['mfa_challenge', 'password_reset'], ['totp'])
      mockClient.POST.mockResolvedValueOnce(ok({ user_id: 'u1', pending: ['password_reset'] }))

      const result = await auth.verifyMfa('totp', '123456', false)

      expect(result).toEqual({ ok: true, complete: false })
      expect(auth.pendingSteps).toEqual(['password_reset'])
      expect(mockClient.POST).toHaveBeenLastCalledWith('/auth/mfa/verify', {
        body: { method: 'totp', code: '123456', remember_device: false },
      })
    })

    it('completes sign-in and loads the user when no steps remain', async () => {
      const auth = await signedInToPendingSteps(['mfa_challenge'], ['totp'])
      mockClient.POST.mockResolvedValueOnce(ok({ user_id: 'u1', pending: [] }))
      mockClient.GET.mockResolvedValueOnce(ok(meData))

      const result = await auth.verifyMfa('totp', '123456', true)

      expect(result).toEqual({ ok: true, complete: true })
      expect(auth.pendingSteps).toEqual([])
      expect(auth.mfaMethods).toEqual([])
      expect(auth.isAuthenticated).toBe(true)
    })

    it('keeps the step on a wrong code', async () => {
      const auth = await signedInToPendingSteps(['mfa_challenge'], ['totp'])
      mockClient.POST.mockResolvedValueOnce(problem(401, PROBLEM_INVALID_CODE, 'invalid verification code'))

      const result = await auth.verifyMfa('totp', '000000', false)

      expect(result.ok).toBe(false)
      expect(result.problemType).toBe(PROBLEM_INVALID_CODE)
      expect(result.error).toBe('That code is not correct. Try again.')
      expect(auth.pendingSteps).toEqual(['mfa_challenge'])
    })

    it('returns to the password form when the sign-in session expired', async () => {
      const auth = await signedInToPendingSteps(['mfa_challenge'], ['totp'])
      mockClient.POST.mockResolvedValueOnce(
        problem(401, PROBLEM_PENDING_SESSION_INVALID, 'invalid or expired pending token'),
      )

      const result = await auth.verifyMfa('totp', '123456', false)

      expect(result.ok).toBe(false)
      expect(result.problemType).toBe(PROBLEM_PENDING_SESSION_INVALID)
      expect(auth.pendingSteps).toEqual([])
      expect(auth.signInNotice).toBe('Your sign-in session expired. Sign in again.')
    })
  })

  describe('completeForcedPasswordChange', () => {
    it('sends only the new password and completes sign-in', async () => {
      const auth = await signedInToPendingSteps(['password_reset'])
      mockClient.POST.mockResolvedValueOnce(ok({}))
      mockClient.GET.mockResolvedValueOnce(ok(meData))

      const result = await auth.completeForcedPasswordChange('a-new-password-1234')

      expect(result).toEqual({ ok: true, complete: true })
      expect(mockClient.POST).toHaveBeenLastCalledWith('/auth/change-password', {
        body: { new_password: 'a-new-password-1234' },
      })
      expect(auth.isAuthenticated).toBe(true)
    })

    it('moves on to mandatory enrollment when it remains', async () => {
      const auth = await signedInToPendingSteps(['password_reset', 'mfa_enrollment_required'])
      mockClient.POST.mockResolvedValueOnce(ok({ pending: ['mfa_enrollment_required'] }))

      const result = await auth.completeForcedPasswordChange('a-new-password-1234')

      expect(result).toEqual({ ok: true, complete: false })
      expect(auth.pendingSteps).toEqual(['mfa_enrollment_required'])
    })
  })

  describe('finishSignIn', () => {
    it('clears the steps and loads the user', async () => {
      const auth = await signedInToPendingSteps(['mfa_enrollment_required'])
      mockClient.GET.mockResolvedValueOnce(ok(meData))

      const result = await auth.finishSignIn()

      expect(result).toEqual({ ok: true, complete: true })
      expect(auth.pendingSteps).toEqual([])
      expect(auth.isAuthenticated).toBe(true)
    })
  })

  describe('expireSignIn', () => {
    it('returns to the password form with the expiry notice', async () => {
      const auth = await signedInToPendingSteps(['mfa_enrollment_required'])

      auth.expireSignIn()

      expect(auth.pendingSteps).toEqual([])
      expect(auth.signInNotice).toBe('Your sign-in session expired. Sign in again.')
    })
  })

  describe('cancelSignIn', () => {
    it('logs out to clear the sign-in cookies and resets the steps', async () => {
      const auth = await signedInToPendingSteps(['mfa_challenge'], ['totp'])
      mockClient.POST.mockResolvedValueOnce(ok(undefined))

      await auth.cancelSignIn()

      expect(mockClient.POST).toHaveBeenLastCalledWith('/auth/logout')
      expect(auth.pendingSteps).toEqual([])
      expect(auth.mfaMethods).toEqual([])
      expect(auth.signInEmail).toBe('')
    })
  })
})
