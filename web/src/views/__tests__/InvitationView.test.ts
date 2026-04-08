// ABOUTME: Tests for the invitation acceptance page.
// ABOUTME: Covers loading, error states, unauthenticated/authenticated flows, and accept logic.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'

let mockRouteParams: Record<string, string> = { token: 'test-token-abc' }
const mockPush = vi.fn<(...args: unknown[]) => unknown>()

vi.mock('vue-router', () => ({
  useRoute: vi.fn<() => { params: Record<string, string> }>(() => ({ params: mockRouteParams })),
  useRouter: vi.fn<() => { push: typeof mockPush }>(() => ({ push: mockPush })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

const mockGET = vi.fn<(...args: unknown[]) => unknown>()
const mockPOST = vi.fn<(...args: unknown[]) => unknown>()

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: (...args: unknown[]) => mockGET(...args),
    POST: (...args: unknown[]) => mockPOST(...args),
  },
}))

async function mountInvitation() {
  const { default: InvitationView } = await import('@/views/InvitationView.vue')
  return mount(InvitationView)
}

describe('InvitationView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()
    mockRouteParams = { token: 'test-token-abc' }
  })

  describe('loading state', () => {
    it('renders loading state initially', async () => {
      mockGET.mockReturnValue(new Promise(() => {})) // never resolves
      const wrapper = await mountInvitation()
      expect(wrapper.text()).toContain('Loading invitation...')
    })
  })

  describe('invitation info', () => {
    it('renders invitation details (org name and role)', async () => {
      mockGET.mockResolvedValue({
        data: { org_name: 'Acme Corp', role: 'member', expires_at: '2026-12-31T00:00:00Z' },
        error: undefined,
      })

      const wrapper = await mountInvitation()
      await flushPromises()

      expect(wrapper.text()).toContain('Acme Corp')
      expect(wrapper.text()).toContain('member')
    })

    it('shows "Log in to accept" for unauthenticated users', async () => {
      mockGET.mockResolvedValue({
        data: { org_name: 'Acme Corp', role: 'member', expires_at: '2026-12-31T00:00:00Z' },
        error: undefined,
      })

      const wrapper = await mountInvitation()
      await flushPromises()

      // User is not authenticated by default
      expect(wrapper.text()).toContain('Log in to accept')
    })

    it('navigates to login with redirect for unauthenticated users', async () => {
      mockGET.mockResolvedValue({
        data: { org_name: 'Acme Corp', role: 'member', expires_at: '2026-12-31T00:00:00Z' },
        error: undefined,
      })

      const wrapper = await mountInvitation()
      await flushPromises()

      const loginLink = wrapper.find('[data-testid="login-link"]')
      expect(loginLink.exists()).toBe(true)
      expect(loginLink.attributes('href')).toBe('/login?redirect=/invitations/test-token-abc')
    })

    it('shows "Accept Invitation" for authenticated users', async () => {
      const auth = useAuthStore()
      auth.user = {
        user_id: 'u1',
        email: 'sam@example.com',
        display_name: 'Sam Carter',
        is_site_admin: false,
        orgs: [],
      }

      mockGET.mockResolvedValue({
        data: { org_name: 'Acme Corp', role: 'member', expires_at: '2026-12-31T00:00:00Z' },
        error: undefined,
      })

      const wrapper = await mountInvitation()
      await flushPromises()

      expect(wrapper.text()).toContain('Accept Invitation')
    })
  })

  describe('error states', () => {
    it('shows error for 404 (invalid link)', async () => {
      mockGET.mockResolvedValue({
        data: undefined,
        error: { status: 404, detail: 'not found' },
        response: { status: 404 },
      })

      const wrapper = await mountInvitation()
      await flushPromises()

      expect(wrapper.text()).toContain('This invitation link is invalid.')
    })

    it('shows error for 410 (expired)', async () => {
      mockGET.mockResolvedValue({
        data: undefined,
        error: { status: 410, detail: 'expired' },
        response: { status: 410 },
      })

      const wrapper = await mountInvitation()
      await flushPromises()

      expect(wrapper.text()).toContain('This invitation has expired or has already been used.')
    })

    it('shows generic error for other failures', async () => {
      mockGET.mockResolvedValue({
        data: undefined,
        error: { status: 500, detail: 'server error' },
        response: { status: 500 },
      })

      const wrapper = await mountInvitation()
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to load invitation details.')
    })
  })

  describe('accept flow', () => {
    it('calls POST, refreshes auth, activates joined org, and navigates to /cves on success', async () => {
      const auth = useAuthStore()
      auth.user = {
        user_id: 'u1',
        email: 'sam@example.com',
        display_name: 'Sam Carter',
        is_site_admin: false,
        orgs: [{ org_id: 'org-old', name: 'Old Org', role: 'admin' }],
      }
      auth.setActiveOrg('org-old')

      mockGET.mockResolvedValue({
        data: { org_name: 'Acme Corp', role: 'member', expires_at: '2026-12-31T00:00:00Z' },
        error: undefined,
      })

      mockPOST.mockResolvedValue({ error: undefined })
      vi.spyOn(auth, 'fetchMe').mockImplementation(async () => {
        // After fetchMe, user now has both orgs
        auth.user = {
          user_id: 'u1',
          email: 'sam@example.com',
          display_name: 'Sam Carter',
          is_site_admin: false,
          orgs: [
            { org_id: 'org-old', name: 'Old Org', role: 'admin' },
            { org_id: 'org-new', name: 'Acme Corp', role: 'member' },
          ],
        }
        return true
      })
      const setActiveOrgSpy = vi.spyOn(auth, 'setActiveOrg')

      const wrapper = await mountInvitation()
      await flushPromises()

      const acceptButton = wrapper.find('[data-testid="accept-button"]')
      expect(acceptButton.exists()).toBe(true)

      await acceptButton.trigger('click')
      await flushPromises()

      expect(mockPOST).toHaveBeenCalledWith('/auth/invitations/{token}/accept', {
        params: { path: { token: 'test-token-abc' } },
      })
      expect(auth.fetchMe).toHaveBeenCalled()
      // Should activate the newly joined org
      expect(setActiveOrgSpy).toHaveBeenCalledWith('org-new')
      expect(mockPush).toHaveBeenCalledWith('/cves')
    })

    it('shows error on 401 accept failure', async () => {
      const auth = useAuthStore()
      auth.user = {
        user_id: 'u1',
        email: 'sam@example.com',
        display_name: 'Sam Carter',
        is_site_admin: false,
        orgs: [],
      }

      mockGET.mockResolvedValue({
        data: { org_name: 'Acme Corp', role: 'member', expires_at: '2026-12-31T00:00:00Z' },
        error: undefined,
      })

      mockPOST.mockResolvedValue({
        error: { status: 401, detail: 'unauthorized' },
        response: { status: 401 },
      })

      const wrapper = await mountInvitation()
      await flushPromises()

      await wrapper.find('[data-testid="accept-button"]').trigger('click')
      await flushPromises()

      expect(wrapper.text()).toContain('Please log in first')
    })

    it('shows error on 403 accept failure (email mismatch)', async () => {
      const auth = useAuthStore()
      auth.user = {
        user_id: 'u1',
        email: 'sam@example.com',
        display_name: 'Sam Carter',
        is_site_admin: false,
        orgs: [],
      }

      mockGET.mockResolvedValue({
        data: { org_name: 'Acme Corp', role: 'member', expires_at: '2026-12-31T00:00:00Z' },
        error: undefined,
      })

      mockPOST.mockResolvedValue({
        error: { status: 403, detail: 'email mismatch' },
        response: { status: 403 },
      })

      const wrapper = await mountInvitation()
      await flushPromises()

      await wrapper.find('[data-testid="accept-button"]').trigger('click')
      await flushPromises()

      expect(wrapper.text()).toContain('This invitation was sent to a different email')
    })

    it('shows error on 410 accept failure (expired)', async () => {
      const auth = useAuthStore()
      auth.user = {
        user_id: 'u1',
        email: 'sam@example.com',
        display_name: 'Sam Carter',
        is_site_admin: false,
        orgs: [],
      }

      mockGET.mockResolvedValue({
        data: { org_name: 'Acme Corp', role: 'member', expires_at: '2026-12-31T00:00:00Z' },
        error: undefined,
      })

      mockPOST.mockResolvedValue({
        error: { status: 410, detail: 'expired' },
        response: { status: 410 },
      })

      const wrapper = await mountInvitation()
      await flushPromises()

      await wrapper.find('[data-testid="accept-button"]').trigger('click')
      await flushPromises()

      expect(wrapper.text()).toContain('Invitation expired')
    })
  })
})
