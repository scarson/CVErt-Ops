// ABOUTME: Auth store -- manages user session, org context, and login/logout.
// ABOUTME: Active org persisted in localStorage for page-refresh survival.

import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import client from '@/lib/api/client'
import type { components } from '@/lib/api/schema'

export type User = components['schemas']['MeOutputBody']
export type UserOrg = components['schemas']['OrgEntry']

const ACTIVE_ORG_KEY = 'activeOrgId'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const activeOrgId = ref<string | null>(null)
  const sessionChecked = ref(false)

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

  async function login(
    email: string,
    password: string,
  ): Promise<{ success: boolean; error?: string }> {
    const { error } = await client.POST('/auth/login', {
      body: { email, password },
    })
    if (error) {
      return { success: false, error: 'Invalid email or password' }
    }
    const fetched = await fetchMe()
    return { success: fetched }
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

  async function logout() {
    await client.POST('/auth/logout')
    clearAuth()
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
    setActiveOrg,
    loadPersistedOrg,
    fetchMe,
    login,
    forgotPassword,
    resetPassword,
    verifyEmail,
    logout,
    clearAuth,
  }
})
