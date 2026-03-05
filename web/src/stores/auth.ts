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

  const isAuthenticated = computed(() => user.value !== null)

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

  async function logout() {
    await client.POST('/auth/logout')
    clearAuth()
  }

  function clearAuth() {
    user.value = null
    activeOrgId.value = null
    localStorage.removeItem(ACTIVE_ORG_KEY)
  }

  return {
    user,
    activeOrgId,
    activeOrg,
    isAuthenticated,
    setActiveOrg,
    loadPersistedOrg,
    fetchMe,
    login,
    logout,
    clearAuth,
  }
})
