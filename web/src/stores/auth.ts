// ABOUTME: Auth store -- manages user session, org context, login/logout, and pending sign-in steps.
// ABOUTME: Active org persisted in localStorage for page-refresh survival.

import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import client from '@/lib/api/client'
import type { components } from '@/lib/api/schema'
import {
  PROBLEM_INVALID_CODE,
  PROBLEM_PENDING_SESSION_INVALID,
  problemDetail,
  problemType,
} from '@/lib/api/problems'

export type User = components['schemas']['MeOutputBody']
export type UserOrg = components['schemas']['OrgEntry']
export type MfaMethod = 'totp' | 'email_otp'
export type MfaVerifyMethod = MfaMethod | 'recovery'

/** Outcome of one sign-in step; `complete` means the user is now fully signed in. */
export interface StepResult {
  ok: boolean
  complete?: boolean
  error?: string
  problemType?: string
}

const ACTIVE_ORG_KEY = 'activeOrgId'
const SIGN_IN_EXPIRED_NOTICE = 'Your sign-in session expired. Sign in again.'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const activeOrgId = ref<string | null>(null)
  const sessionChecked = ref(false)

  // Pending sign-in: the steps the server still requires after the password
  // (mfa_challenge, password_reset, mfa_enrollment_required), in server order.
  // The pending token itself is an HttpOnly cookie the SPA cannot read.
  const pendingSteps = ref<string[]>([])
  const mfaMethods = ref<string[]>([])
  const signInEmail = ref('')
  const signInNotice = ref('')

  const isAuthenticated = computed(() => user.value !== null)
  const isSiteAdmin = computed(() => user.value?.is_site_admin === true)

  const activeOrg = computed(() => {
    if (!user.value || !activeOrgId.value) return null
    return user.value.orgs?.find((o) => o.org_id === activeOrgId.value) ?? null
  })

  function setActiveOrg(orgId: string) {
    activeOrgId.value = orgId
    localStorage.setItem(ACTIVE_ORG_KEY, orgId)
  }

  function loadPersistedOrg() {
    const stored = localStorage.getItem(ACTIVE_ORG_KEY)
    if (stored) {
      activeOrgId.value = stored
    }
  }

  async function fetchMe(): Promise<boolean> {
    const { data, error } = await client.GET('/auth/me')
    sessionChecked.value = true
    if (error || !data) {
      return false
    }
    user.value = data
    loadPersistedOrg()

    // Validate persisted org is still in user's org list.
    if (activeOrgId.value) {
      const stillMember = user.value.orgs?.some((o) => o.org_id === activeOrgId.value) ?? false
      if (!stillMember) {
        activeOrgId.value = null
        localStorage.removeItem(ACTIVE_ORG_KEY)
      }
    }

    // Auto-select if user has exactly one org.
    if (!activeOrgId.value && user.value.orgs?.length === 1) {
      setActiveOrg(user.value.orgs[0]!.org_id)
    }

    return true
  }

  // Signs in with email and password. `success` means fully signed in; when the
  // server requires more steps, `pendingSteps` is set and success is false
  // without an error.
  async function login(
    email: string,
    password: string,
  ): Promise<{ success: boolean; error?: string }> {
    signInNotice.value = ''
    const { data, error, response } = await client.POST('/auth/login', {
      body: { email, password },
    })
    if (error) {
      if (response.status === 401) {
        return { success: false, error: 'Invalid email or password' }
      }
      return { success: false, error: problemDetail(error, 'Login failed') }
    }
    const pending = data?.pending ?? []
    if (pending.length > 0) {
      pendingSteps.value = pending
      mfaMethods.value = data?.methods ?? []
      signInEmail.value = email
      return { success: false }
    }
    const fetched = await fetchMe()
    return { success: fetched }
  }

  function resetSignIn() {
    pendingSteps.value = []
    mfaMethods.value = []
    signInEmail.value = ''
  }

  // Records the steps a completed step leaves; with none left, loads the user.
  async function advanceSignIn(pending: string[] | null | undefined): Promise<StepResult> {
    if (pending && pending.length > 0) {
      pendingSteps.value = pending
      return { ok: true, complete: false }
    }
    return finishSignIn()
  }

  // Ends the step flow once the server has issued full session cookies.
  async function finishSignIn(): Promise<StepResult> {
    resetSignIn()
    const fetched = await fetchMe()
    if (!fetched) {
      return { ok: false, error: 'Sign-in could not be completed. Sign in again.' }
    }
    return { ok: true, complete: true }
  }

  // Sends the user back to the password form after the server rejected the
  // sign-in session (expired, invalidated, or belonging to another user).
  function expireSignIn() {
    resetSignIn()
    signInNotice.value = SIGN_IN_EXPIRED_NOTICE
  }

  // Maps a failed step to a result; an invalid sign-in session sends the user
  // back to the password form.
  function stepFailure(error: unknown, fallback: string): StepResult {
    const type = problemType(error)
    if (type === PROBLEM_PENDING_SESSION_INVALID) {
      expireSignIn()
      return { ok: false, problemType: type, error: SIGN_IN_EXPIRED_NOTICE }
    }
    if (type === PROBLEM_INVALID_CODE) {
      return { ok: false, problemType: type, error: 'That code is not correct. Try again.' }
    }
    return { ok: false, problemType: type, error: problemDetail(error, fallback) }
  }

  // Asks the server to send an email code, or renews the session for TOTP.
  async function startMfaChallenge(method: MfaMethod): Promise<StepResult> {
    const { error } = await client.POST('/auth/mfa/challenge', { body: { method } })
    if (error) return stepFailure(error, 'Could not start verification')
    return { ok: true }
  }

  async function verifyMfa(
    method: MfaVerifyMethod,
    code: string,
    rememberDevice: boolean,
  ): Promise<StepResult> {
    const { data, error } = await client.POST('/auth/mfa/verify', {
      body: { method, code, remember_device: rememberDevice },
    })
    if (error) return stepFailure(error, 'Verification failed')
    return advanceSignIn(data?.pending)
  }

  // Sets a new password for a forced reset during sign-in. The server does not
  // ask for the current password here: it may be the compromised one.
  async function completeForcedPasswordChange(newPassword: string): Promise<StepResult> {
    const { data, error } = await client.POST('/auth/change-password', {
      body: { new_password: newPassword },
    })
    if (error) return stepFailure(error, 'Password change failed')
    return advanceSignIn(data?.pending)
  }

  // Abandons a pending sign-in. Logout expires the pending and enrollment cookies.
  async function cancelSignIn() {
    await client.POST('/auth/logout')
    resetSignIn()
    signInNotice.value = ''
  }

  async function forgotPassword(email: string): Promise<{ success: boolean; error?: string }> {
    const { error } = await client.POST('/auth/forgot-password', {
      body: { email },
    })
    if (error) {
      return { success: false, error: (error as { detail?: string }).detail ?? 'Request failed' }
    }
    return { success: true }
  }

  async function resetPassword(
    token: string,
    newPassword: string,
  ): Promise<{ success: boolean; error?: string }> {
    const { error } = await client.POST('/auth/reset-password', {
      body: { token, new_password: newPassword },
    })
    if (error) {
      return { success: false, error: (error as { detail?: string }).detail ?? 'Reset failed' }
    }
    return { success: true }
  }

  async function verifyEmail(token: string): Promise<{ success: boolean; error?: string }> {
    const { error } = await client.POST('/auth/verify-email', {
      body: { token },
    })
    if (error) {
      return { success: false, error: (error as { detail?: string }).detail ?? 'Verification failed' }
    }
    return { success: true }
  }

  // Clears local state only after the server has revoked the session; on failure the
  // session cookies are still valid, so the user must not be shown as logged out.
  async function logout(): Promise<{ success: boolean; error?: string }> {
    const { error } = await client.POST('/auth/logout')
    if (error) {
      return { success: false, error: (error as { detail?: string }).detail ?? 'Logout failed' }
    }
    clearAuth()
    return { success: true }
  }

  function clearAuth() {
    user.value = null
    activeOrgId.value = null
    sessionChecked.value = false
    localStorage.removeItem(ACTIVE_ORG_KEY)
  }

  return {
    user,
    activeOrgId,
    activeOrg,
    isAuthenticated,
    isSiteAdmin,
    sessionChecked,
    pendingSteps,
    mfaMethods,
    signInEmail,
    signInNotice,
    setActiveOrg,
    loadPersistedOrg,
    fetchMe,
    login,
    startMfaChallenge,
    verifyMfa,
    completeForcedPasswordChange,
    finishSignIn,
    expireSignIn,
    cancelSignIn,
    forgotPassword,
    resetPassword,
    verifyEmail,
    logout,
    clearAuth,
  }
})
