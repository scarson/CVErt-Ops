// ABOUTME: Tests for the members management page view.
// ABOUTME: Covers member listing, role changes, removal, invitations, and RBAC visibility.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises, VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'

const mockPush = vi.fn<(...args: unknown[]) => unknown>()

vi.mock('vue-router', () => ({
  useRoute: vi.fn<() => unknown>(() => ({ params: {} })),
  useRouter: vi.fn<() => unknown>(() => ({ push: mockPush })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

const mockGET = vi.fn<(...args: unknown[]) => unknown>()
const mockPATCH = vi.fn<(...args: unknown[]) => unknown>()
const mockDELETE = vi.fn<(...args: unknown[]) => unknown>()

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: (...args: unknown[]) => mockGET(...args),
    POST: vi.fn<(...args: unknown[]) => unknown>(),
    PATCH: (...args: unknown[]) => mockPATCH(...args),
    DELETE: (...args: unknown[]) => mockDELETE(...args),
  },
}))

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000001'
const TEST_USER_ID = '00000000-0000-0000-0000-000000000099'

function makeMember(overrides: Record<string, unknown> = {}) {
  return {
    user_id: 'user-001',
    email: 'alice@example.com',
    display_name: 'Alice Smith',
    role: 'member',
    joined_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

function makeInvitation(overrides: Record<string, unknown> = {}) {
  return {
    id: 'inv-001',
    email: 'pending@example.com',
    role: 'member',
    expires_at: '2025-01-08T00:00:00Z',
    created_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

function mockMembersSuccess(members = [makeMember()]) {
  mockGET.mockResolvedValueOnce({
    data: { items: members },
    error: undefined,
  })
}

function mockInvitationsSuccess(invitations = [makeInvitation()]) {
  mockGET.mockResolvedValueOnce({
    data: { items: invitations },
    error: undefined,
  })
}

function mockMembersError() {
  mockGET.mockResolvedValueOnce({
    data: undefined,
    error: { status: 500, detail: 'Internal Server Error' },
  })
}

function mockDeleteSuccess() {
  mockDELETE.mockResolvedValueOnce({
    data: undefined,
    error: undefined,
  })
}

function mockPatchSuccess(userId: string, role: string) {
  mockPATCH.mockResolvedValueOnce({
    data: { user_id: userId, role },
    error: undefined,
  })
}

// Dialog/AlertDialog content renders via portal to document.body.
function findTestId(id: string): HTMLElement | null {
  return document.querySelector(`[data-testid="${id}"]`)
}

function bodyText(): string {
  return document.body.textContent ?? ''
}

function setupAuthStore(role: string) {
  const auth = useAuthStore()
  auth.activeOrgId = TEST_ORG_ID
  auth.user = {
    user_id: TEST_USER_ID,
    email: 'me@example.com',
    display_name: 'Current User',
    orgs: [{ org_id: TEST_ORG_ID, name: 'Test Org', role }],
  } as any
  return auth
}

// Open a reka-ui Select trigger and return the rendered option texts.
// JSDOM lacks pointer capture APIs that reka-ui needs, so we polyfill them.
async function openRoleSelectAndGetOptions(): Promise<string[]> {
  const trigger = findTestId('role-select-trigger')
  if (!trigger) throw new Error('role-select-trigger not found')
  if (!trigger.hasPointerCapture) {
    trigger.hasPointerCapture = () => false
    trigger.releasePointerCapture = () => {}
  }
  trigger.dispatchEvent(
    new PointerEvent('pointerdown', { bubbles: true, cancelable: true, button: 0, pointerId: 1 }),
  )
  await flushPromises()
  const options = document.querySelectorAll('[role="option"]')
  return Array.from(options).map((el) => el.textContent?.trim() ?? '')
}

let wrapper: VueWrapper

async function mountView() {
  const { default: MembersView } = await import('@/views/MembersView.vue')
  wrapper = mount(MembersView, {
    attachTo: document.body,
  })
  return wrapper
}

// Clean up portaled DOM elements (reka-ui Select, AlertDialog, Dialog)
function cleanupPortals() {
  document
    .querySelectorAll('[data-reka-portal], [data-radix-popper-content-wrapper]')
    .forEach((el) => el.remove())
}

describe('MembersView', () => {
  beforeEach(() => {
    const pinia = createPinia()
    setActivePinia(pinia)
    vi.clearAllMocks()
    mockGET.mockReset()
    mockPATCH.mockReset()
    mockDELETE.mockReset()
  })

  afterEach(() => {
    wrapper?.unmount()
    cleanupPortals()
  })

  describe('loading state', () => {
    it('shows loading indicator while fetching', async () => {
      setupAuthStore('admin')
      mockGET.mockImplementation(() => new Promise(() => {}))
      await mountView()

      expect(wrapper.text()).toContain('Loading')
    })
  })

  describe('error state', () => {
    it('shows error message on fetch failure', async () => {
      setupAuthStore('admin')
      mockMembersError()
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to load members')
    })
  })

  describe('rendering with data', () => {
    it('renders page title and subtitle', async () => {
      setupAuthStore('admin')
      mockMembersSuccess()
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Members')
      expect(wrapper.text()).toContain('Manage team members and roles')
    })

    it('renders members table with data', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([
        makeMember({
          user_id: 'u1',
          email: 'alice@example.com',
          display_name: 'Alice',
          role: 'admin',
        }),
        makeMember({
          user_id: 'u2',
          email: 'bob@example.com',
          display_name: 'Bob',
          role: 'member',
        }),
      ])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('alice@example.com')
      expect(wrapper.text()).toContain('bob@example.com')
      expect(wrapper.text()).toContain('Alice')
      expect(wrapper.text()).toContain('Bob')
    })

    it('shows role badges for each member', async () => {
      // Use viewer role so all members display as badges (not Select dropdowns)
      setupAuthStore('viewer')
      mockMembersSuccess([
        makeMember({ user_id: 'u1', role: 'owner' }),
        makeMember({ user_id: 'u2', role: 'admin' }),
        makeMember({ user_id: 'u3', role: 'member' }),
        makeMember({ user_id: 'u4', role: 'viewer' }),
      ])
      await mountView()
      await flushPromises()

      const badges = wrapper.findAll('[data-testid="member-role-badge"]')
      expect(badges.length).toBe(4)
    })

    it('formats joined date', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([makeMember({ joined_at: '2025-01-15T00:00:00Z' })])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Jan')
      expect(wrapper.text()).toContain('2025')
    })
  })

  describe('RBAC: invite button visibility', () => {
    it('shows invite button for admin users', async () => {
      setupAuthStore('admin')
      mockMembersSuccess()
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="invite-member-btn"]')
      expect(btn.exists()).toBe(true)
    })

    it('shows invite button for owner users', async () => {
      setupAuthStore('owner')
      mockMembersSuccess()
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="invite-member-btn"]')
      expect(btn.exists()).toBe(true)
    })

    it('hides invite button for member users', async () => {
      setupAuthStore('member')
      mockMembersSuccess()
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="invite-member-btn"]')
      expect(btn.exists()).toBe(false)
    })

    it('hides invite button for viewer users', async () => {
      setupAuthStore('viewer')
      mockMembersSuccess()
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="invite-member-btn"]')
      expect(btn.exists()).toBe(false)
    })
  })

  describe('accessibility', () => {
    it('has accessible labels on remove member button', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([
        makeMember({ user_id: 'u1', role: 'member', email: 'member@example.com' }),
      ])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      const removeBtn = findTestId('remove-member-btn')
      expect(removeBtn).not.toBeNull()
      expect(removeBtn!.getAttribute('aria-label')).toBe('Remove member')
    })

    it('has accessible labels on cancel invitation button', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([makeMember()])
      mockInvitationsSuccess([makeInvitation()])
      await mountView()
      await flushPromises()

      const cancelBtn = findTestId('cancel-invitation-btn')
      expect(cancelBtn).not.toBeNull()
      expect(cancelBtn!.getAttribute('aria-label')).toBe('Cancel invitation')
    })
  })

  describe('RBAC: remove button visibility', () => {
    it('shows remove button for admin on non-owner members', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([
        makeMember({ user_id: 'u1', role: 'member', email: 'member@example.com' }),
      ])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="remove-member-btn"]')
      expect(btn.exists()).toBe(true)
    })

    it('hides remove button on owner members', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([makeMember({ user_id: 'u1', role: 'owner', email: 'owner@example.com' })])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="remove-member-btn"]')
      expect(btn.exists()).toBe(false)
    })

    it('hides remove button for non-admin users', async () => {
      setupAuthStore('member')
      mockMembersSuccess([
        makeMember({ user_id: 'u1', role: 'member', email: 'other@example.com' }),
      ])
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="remove-member-btn"]')
      expect(btn.exists()).toBe(false)
    })
  })

  describe('remove member flow', () => {
    it('shows confirmation dialog when remove is clicked', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([makeMember({ user_id: 'u1', role: 'member' })])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      await wrapper.find('[data-testid="remove-member-btn"]').trigger('click')
      await flushPromises()

      expect(bodyText()).toContain('Remove member')
      expect(bodyText()).toContain('lose access')
    })

    it('calls DELETE on confirmation and removes from list', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([
        makeMember({
          user_id: 'u1',
          email: 'keep@example.com',
          display_name: 'Keep',
          role: 'member',
        }),
        makeMember({
          user_id: 'u2',
          email: 'remove@example.com',
          display_name: 'Remove',
          role: 'member',
        }),
      ])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      mockDELETE.mockReset()
      mockDeleteSuccess()

      // Click remove on second member
      const removeBtns = wrapper.findAll('[data-testid="remove-member-btn"]')
      expect(removeBtns.length).toBe(2)
      await removeBtns[1]!.trigger('click')
      await flushPromises()

      // Confirm via portal button
      const confirmBtn = findTestId('confirm-remove-btn')
      expect(confirmBtn).not.toBeNull()
      confirmBtn!.click()
      await flushPromises()

      expect(mockDELETE).toHaveBeenCalledWith(
        '/orgs/{org_id}/members/{user_id}',
        expect.objectContaining({
          params: { path: { org_id: TEST_ORG_ID, user_id: 'u2' } },
        }),
      )

      expect(wrapper.text()).toContain('keep@example.com')
      expect(wrapper.text()).not.toContain('remove@example.com')
    })
  })

  describe('role change', () => {
    it('admin role Select dropdown includes admin, member, and viewer options', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([
        makeMember({ user_id: 'u1', role: 'member', email: 'target@example.com' }),
      ])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      const optionTexts = await openRoleSelectAndGetOptions()
      expect(optionTexts).toEqual(['Admin', 'Member', 'Viewer'])
    })

    it('role Select trigger displays the member current role', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([
        makeMember({ user_id: 'u1', role: 'viewer', email: 'target@example.com' }),
      ])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      const trigger = findTestId('role-select-trigger')
      expect(trigger).not.toBeNull()
      expect(trigger!.textContent?.trim()).toContain('Viewer')
    })

    it('shows role select for admin on non-owner members', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([makeMember({ user_id: 'u1', role: 'member' })])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      const roleSelect = wrapper.find('[data-testid="role-select-trigger"]')
      expect(roleSelect.exists()).toBe(true)
    })

    it('shows plain text role for owner members (not changeable)', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([makeMember({ user_id: 'u1', role: 'owner' })])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      const roleSelect = wrapper.find('[data-testid="role-select-trigger"]')
      expect(roleSelect.exists()).toBe(false)

      const badge = wrapper.find('[data-testid="member-role-badge"]')
      expect(badge.exists()).toBe(true)
      expect(badge.text()).toContain('owner')
    })

    it('calls PATCH when role is changed', async () => {
      setupAuthStore('owner')
      mockMembersSuccess([makeMember({ user_id: 'u1', role: 'member' })])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      mockPATCH.mockReset()
      mockPatchSuccess('u1', 'viewer')

      // Use exposed changeRole method since reka-ui Select is hard to trigger in JSDOM.
      const view = wrapper.vm as any
      await view.changeRole('u1', 'viewer')
      await flushPromises()

      expect(mockPATCH).toHaveBeenCalledWith(
        '/orgs/{org_id}/members/{user_id}',
        expect.objectContaining({
          params: { path: { org_id: TEST_ORG_ID, user_id: 'u1' } },
          body: { role: 'viewer' },
        }),
      )
    })

    it('shows plain text role badge for non-admin users', async () => {
      setupAuthStore('viewer')
      mockMembersSuccess([makeMember({ user_id: 'u1', role: 'member' })])
      await mountView()
      await flushPromises()

      const roleSelect = wrapper.find('[data-testid="role-select-trigger"]')
      expect(roleSelect.exists()).toBe(false)

      const badge = wrapper.find('[data-testid="member-role-badge"]')
      expect(badge.exists()).toBe(true)
    })
  })

  describe('pending invitations', () => {
    it('renders pending invitations section when invitations exist', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([makeMember()])
      mockInvitationsSuccess([makeInvitation()])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Pending Invitations')
      expect(wrapper.text()).toContain('pending@example.com')
    })

    it('hides invitations section when no invitations', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([makeMember()])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).not.toContain('Pending Invitations')
    })

    it('cancel invitation calls DELETE and removes from list', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([makeMember()])
      mockInvitationsSuccess([
        makeInvitation({ id: 'inv-1', email: 'stay@example.com' }),
        makeInvitation({ id: 'inv-2', email: 'cancel@example.com' }),
      ])
      await mountView()
      await flushPromises()

      mockDELETE.mockReset()
      mockDeleteSuccess()

      const cancelBtns = wrapper.findAll('[data-testid="cancel-invitation-btn"]')
      expect(cancelBtns.length).toBe(2)
      await cancelBtns[1]!.trigger('click')
      await flushPromises()

      expect(mockDELETE).toHaveBeenCalledWith(
        '/orgs/{org_id}/invitations/{id}',
        expect.objectContaining({
          params: { path: { org_id: TEST_ORG_ID, id: 'inv-2' } },
        }),
      )

      expect(wrapper.text()).toContain('stay@example.com')
      expect(wrapper.text()).not.toContain('cancel@example.com')
    })

    it('shows error when cancelling invitation fails', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([makeMember()])
      mockInvitationsSuccess([makeInvitation({ id: 'inv-1', email: 'fail@example.com' })])
      await mountView()
      await flushPromises()

      mockDELETE.mockReset()
      mockDELETE.mockResolvedValueOnce({
        data: undefined,
        error: { status: 500, detail: 'Server error' },
      })

      const cancelBtns = wrapper.findAll('[data-testid="cancel-invitation-btn"]')
      await cancelBtns[0]!.trigger('click')
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to cancel invitation')
      // Invitation should still be in the list
      expect(wrapper.text()).toContain('fail@example.com')
    })
  })

  describe('role change error handling', () => {
    it('reverts role display and shows error when PATCH fails', async () => {
      setupAuthStore('owner')
      mockMembersSuccess([makeMember({ user_id: 'u1', role: 'admin', email: 'admin@example.com' })])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      mockPATCH.mockReset()
      // Mock failed PATCH
      mockPATCH.mockResolvedValueOnce({
        data: undefined,
        error: { status: 403, detail: 'Forbidden' },
      })

      const view = wrapper.vm as any
      await view.changeRole('u1', 'member')
      await flushPromises()

      // Error should be displayed
      expect(wrapper.text()).toContain('Failed to change role')
    })
  })

  describe('remove member error handling', () => {
    it('shows error and keeps dialog open when DELETE fails', async () => {
      setupAuthStore('admin')
      mockMembersSuccess([
        makeMember({ user_id: 'u1', role: 'member', email: 'target@example.com' }),
      ])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      await wrapper.find('[data-testid="remove-member-btn"]').trigger('click')
      await flushPromises()

      mockDELETE.mockReset()
      mockDELETE.mockResolvedValueOnce({
        data: undefined,
        error: { status: 500, detail: 'Server error' },
      })

      const confirmBtn = findTestId('confirm-remove-btn')
      confirmBtn!.click()
      await flushPromises()

      // Member should still be in the list
      expect(wrapper.text()).toContain('target@example.com')
      // Error should appear in the dialog
      expect(bodyText()).toContain('Failed to remove member')
    })
  })

  describe('org switch re-fetch', () => {
    it('re-fetches members when activeOrgId changes', async () => {
      const auth = setupAuthStore('admin')
      mockMembersSuccess([makeMember({ email: 'alice@example.com' })])
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      mockGET.mockClear()
      const ORG_B_ID = '00000000-0000-0000-0000-000000000002'
      mockMembersSuccess([makeMember({ email: 'bob@example.com' })])
      mockInvitationsSuccess([])

      auth.activeOrgId = ORG_B_ID
      await flushPromises()

      expect(mockGET).toHaveBeenCalledWith(
        '/orgs/{org_id}/members',
        expect.objectContaining({
          params: { path: { org_id: ORG_B_ID } },
        }),
      )
    })
  })

  describe('API integration', () => {
    it('fetches members with correct URL and options', async () => {
      setupAuthStore('admin')
      mockMembersSuccess()
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      expect(mockGET).toHaveBeenCalledWith(
        '/orgs/{org_id}/members',
        expect.objectContaining({
          params: { path: { org_id: TEST_ORG_ID } },
        }),
      )
    })

    it('fetches invitations with correct URL', async () => {
      setupAuthStore('admin')
      mockMembersSuccess()
      mockInvitationsSuccess([])
      await mountView()
      await flushPromises()

      expect(mockGET).toHaveBeenCalledWith(
        '/orgs/{org_id}/invitations',
        expect.objectContaining({
          params: { path: { org_id: TEST_ORG_ID } },
        }),
      )
    })
  })
})
