// ABOUTME: Tests for the auth Pinia store.
// ABOUTME: Verifies login, logout, org selection, and session persistence.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAuthStore } from '../auth'

// Mock the API client
vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn(),
    POST: vi.fn(),
  },
}))

import client from '@/lib/api/client'

describe('auth store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.resetAllMocks()
  })

  describe('initial state', () => {
    it('starts with no user and not authenticated', () => {
      const auth = useAuthStore()
      expect(auth.isAuthenticated).toBe(false)
      expect(auth.user).toBeNull()
      expect(auth.activeOrgId).toBeNull()
    })
  })

  describe('setActiveOrg', () => {
    it('sets activeOrgId and persists to localStorage', () => {
      const auth = useAuthStore()
      const orgId = '550e8400-e29b-41d4-a716-446655440001'
      auth.setActiveOrg(orgId)
      expect(auth.activeOrgId).toBe(orgId)
      expect(localStorage.getItem('activeOrgId')).toBe(orgId)
    })
  })

  describe('loadPersistedOrg', () => {
    it('loads activeOrgId from localStorage', () => {
      const orgId = '550e8400-e29b-41d4-a716-446655440001'
      localStorage.setItem('activeOrgId', orgId)
      const auth = useAuthStore()
      auth.loadPersistedOrg()
      expect(auth.activeOrgId).toBe(orgId)
    })

    it('does nothing when localStorage has no activeOrgId', () => {
      const auth = useAuthStore()
      auth.loadPersistedOrg()
      expect(auth.activeOrgId).toBeNull()
    })
  })

  describe('activeOrg computed', () => {
    it('returns null when no user', () => {
      const auth = useAuthStore()
      auth.setActiveOrg('some-org-id')
      expect(auth.activeOrg).toBeNull()
    })

    it('returns the matching org from user orgs', () => {
      const auth = useAuthStore()
      const orgId = '550e8400-e29b-41d4-a716-446655440001'
      auth.user = {
        user_id: 'u1',
        email: 'test@example.com',
        display_name: 'Test',
        orgs: [{ org_id: orgId, name: 'My Org', role: 'admin' }],
      }
      auth.setActiveOrg(orgId)
      expect(auth.activeOrg).toEqual({ org_id: orgId, name: 'My Org', role: 'admin' })
    })

    it('returns null when activeOrgId does not match any user org', () => {
      const auth = useAuthStore()
      auth.user = {
        user_id: 'u1',
        email: 'test@example.com',
        display_name: 'Test',
        orgs: [{ org_id: 'org-a', name: 'Org A', role: 'member' }],
      }
      auth.setActiveOrg('nonexistent-org')
      expect(auth.activeOrg).toBeNull()
    })
  })

  describe('clearAuth', () => {
    it('clears all auth state and localStorage', () => {
      const auth = useAuthStore()
      auth.user = {
        user_id: 'u1',
        email: 'test@example.com',
        display_name: 'Test',
        orgs: [],
      }
      auth.setActiveOrg('some-org-id')
      auth.clearAuth()
      expect(auth.isAuthenticated).toBe(false)
      expect(auth.user).toBeNull()
      expect(auth.activeOrgId).toBeNull()
      expect(localStorage.getItem('activeOrgId')).toBeNull()
    })
  })

  describe('fetchMe', () => {
    it('sets user from API response', async () => {
      const meData = {
        user_id: 'u1',
        email: 'test@example.com',
        display_name: 'Test User',
        orgs: [{ org_id: 'org-1', name: 'Org One', role: 'owner' }],
      }
      vi.mocked(client.GET).mockResolvedValue({ data: meData, error: undefined, response: {} as Response })

      const auth = useAuthStore()
      const result = await auth.fetchMe()

      expect(result).toBe(true)
      expect(auth.user).toEqual(meData)
      expect(auth.isAuthenticated).toBe(true)
    })

    it('returns false on API error', async () => {
      vi.mocked(client.GET).mockResolvedValue({ data: undefined, error: { detail: 'unauthorized' }, response: {} as Response })

      const auth = useAuthStore()
      const result = await auth.fetchMe()

      expect(result).toBe(false)
      expect(auth.user).toBeNull()
    })

    it('auto-selects org when user has exactly one', async () => {
      const meData = {
        user_id: 'u1',
        email: 'test@example.com',
        display_name: 'Test',
        orgs: [{ org_id: 'only-org', name: 'Only Org', role: 'admin' }],
      }
      vi.mocked(client.GET).mockResolvedValue({ data: meData, error: undefined, response: {} as Response })

      const auth = useAuthStore()
      await auth.fetchMe()

      expect(auth.activeOrgId).toBe('only-org')
      expect(localStorage.getItem('activeOrgId')).toBe('only-org')
    })

    it('does not auto-select org when user has multiple orgs', async () => {
      const meData = {
        user_id: 'u1',
        email: 'test@example.com',
        display_name: 'Test',
        orgs: [
          { org_id: 'org-1', name: 'Org One', role: 'admin' },
          { org_id: 'org-2', name: 'Org Two', role: 'member' },
        ],
      }
      vi.mocked(client.GET).mockResolvedValue({ data: meData, error: undefined, response: {} as Response })

      const auth = useAuthStore()
      await auth.fetchMe()

      expect(auth.activeOrgId).toBeNull()
    })

    it('clears persisted org if user is no longer a member', async () => {
      localStorage.setItem('activeOrgId', 'removed-org')
      const meData = {
        user_id: 'u1',
        email: 'test@example.com',
        display_name: 'Test',
        orgs: [{ org_id: 'current-org', name: 'Current', role: 'admin' }],
      }
      vi.mocked(client.GET).mockResolvedValue({ data: meData, error: undefined, response: {} as Response })

      const auth = useAuthStore()
      await auth.fetchMe()

      // The persisted org was invalid, so it should be cleared and auto-select kicks in.
      expect(auth.activeOrgId).toBe('current-org')
      expect(localStorage.getItem('activeOrgId')).toBe('current-org')
    })

    it('restores persisted org if user is still a member', async () => {
      localStorage.setItem('activeOrgId', 'org-2')
      const meData = {
        user_id: 'u1',
        email: 'test@example.com',
        display_name: 'Test',
        orgs: [
          { org_id: 'org-1', name: 'Org One', role: 'admin' },
          { org_id: 'org-2', name: 'Org Two', role: 'member' },
        ],
      }
      vi.mocked(client.GET).mockResolvedValue({ data: meData, error: undefined, response: {} as Response })

      const auth = useAuthStore()
      await auth.fetchMe()

      expect(auth.activeOrgId).toBe('org-2')
    })
  })

  describe('login', () => {
    it('returns success and fetches user on successful login', async () => {
      const meData = {
        user_id: 'u1',
        email: 'test@example.com',
        display_name: 'Test',
        orgs: [{ org_id: 'org-1', name: 'Org One', role: 'admin' }],
      }
      vi.mocked(client.POST).mockResolvedValue({ data: undefined, error: undefined, response: {} as Response })
      vi.mocked(client.GET).mockResolvedValue({ data: meData, error: undefined, response: {} as Response })

      const auth = useAuthStore()
      const result = await auth.login('test@example.com', 'password123')

      expect(result.success).toBe(true)
      expect(result.error).toBeUndefined()
      expect(auth.isAuthenticated).toBe(true)
    })

    it('returns error on failed login', async () => {
      vi.mocked(client.POST).mockResolvedValue({ data: undefined, error: { detail: 'bad creds' }, response: {} as Response })

      const auth = useAuthStore()
      const result = await auth.login('bad@example.com', 'wrong')

      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid email or password')
      expect(auth.isAuthenticated).toBe(false)
    })
  })

  describe('logout', () => {
    it('calls logout endpoint and clears auth state', async () => {
      vi.mocked(client.POST).mockResolvedValue({ data: undefined, error: undefined, response: {} as Response })

      const auth = useAuthStore()
      auth.user = {
        user_id: 'u1',
        email: 'test@example.com',
        display_name: 'Test',
        orgs: [],
      }
      auth.setActiveOrg('some-org')

      await auth.logout()

      expect(client.POST).toHaveBeenCalledWith('/auth/logout')
      expect(auth.isAuthenticated).toBe(false)
      expect(auth.user).toBeNull()
      expect(auth.activeOrgId).toBeNull()
      expect(localStorage.getItem('activeOrgId')).toBeNull()
    })
  })
})
