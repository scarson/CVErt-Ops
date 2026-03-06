// ABOUTME: Tests for the group members management dialog component.
// ABOUTME: Covers member listing, adding members, removing members, loading state, and API calls.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises, VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ params: {} })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000001'
const TEST_GROUP_ID = 'grp-001'

function makeGroupMember(overrides: Record<string, unknown> = {}) {
  return {
    user_id: 'user-001',
    email: 'alice@example.com',
    display_name: 'Alice Smith',
    joined_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

function makeOrgMember(overrides: Record<string, unknown> = {}) {
  return {
    user_id: 'user-001',
    email: 'alice@example.com',
    display_name: 'Alice Smith',
    role: 'member',
    joined_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

function mockGroupMembersSuccess(members = [makeGroupMember()]) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 200,
    json: () => Promise.resolve(members),
  })
}

function mockOrgMembersSuccess(members = [makeOrgMember()]) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 200,
    json: () => Promise.resolve(members),
  })
}

function mockAddMemberSuccess() {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 204,
    json: () => Promise.resolve(null),
  })
}

function mockRemoveMemberSuccess() {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 204,
    json: () => Promise.resolve(null),
  })
}

// Dialog content renders inside a portal (teleported to body).
function findAllTestId(id: string): NodeListOf<HTMLElement> {
  return document.querySelectorAll(`[data-testid="${id}"]`)
}

function bodyText(): string {
  return document.body.textContent ?? ''
}

let wrapper: VueWrapper

async function mountDialog(props: { open?: boolean; groupId?: string; groupName?: string } = {}) {
  const { default: GroupMembersDialog } = await import(
    '@/components/settings/GroupMembersDialog.vue'
  )
  wrapper = mount(GroupMembersDialog, {
    props: {
      open: true,
      groupId: TEST_GROUP_ID,
      groupName: 'Engineering',
      ...props,
    },
    attachTo: document.body,
  })
  return wrapper
}

// Clean up portaled DOM elements
function cleanupPortals() {
  document.querySelectorAll('[data-reka-portal], [data-radix-popper-content-wrapper]').forEach((el) => el.remove())
}

describe('GroupMembersDialog', () => {
  beforeEach(() => {
    const pinia = createPinia()
    setActivePinia(pinia)
    vi.clearAllMocks()
    mockFetch.mockReset()

    const auth = useAuthStore()
    auth.activeOrgId = TEST_ORG_ID
  })

  afterEach(() => {
    wrapper?.unmount()
    cleanupPortals()
  })

  describe('loading state', () => {
    it('shows loading indicator while fetching members', async () => {
      mockFetch.mockImplementation(() => new Promise(() => {}))
      await mountDialog()
      await flushPromises()

      expect(bodyText()).toContain('Loading')
    })
  })

  describe('rendering members', () => {
    it('renders group members list', async () => {
      mockGroupMembersSuccess([
        makeGroupMember({ user_id: 'u1', display_name: 'Alice', email: 'alice@example.com' }),
        makeGroupMember({ user_id: 'u2', display_name: 'Bob', email: 'bob@example.com' }),
      ])
      mockOrgMembersSuccess([])
      await mountDialog()
      await flushPromises()

      expect(bodyText()).toContain('Alice')
      expect(bodyText()).toContain('alice@example.com')
      expect(bodyText()).toContain('Bob')
      expect(bodyText()).toContain('bob@example.com')
    })

    it('shows group name in dialog title', async () => {
      mockGroupMembersSuccess([])
      mockOrgMembersSuccess([])
      await mountDialog({ groupName: 'Security Team' })
      await flushPromises()

      expect(bodyText()).toContain('Security Team')
    })
  })

  describe('accessibility', () => {
    it('has accessible labels on remove member button', async () => {
      mockGroupMembersSuccess([makeGroupMember({ user_id: 'u1' })])
      mockOrgMembersSuccess([])
      await mountDialog()
      await flushPromises()

      const removeBtns = findAllTestId('remove-group-member-btn')
      expect(removeBtns.length).toBe(1)
      expect(removeBtns[0]!.getAttribute('aria-label')).toBe('Remove member')
    })
  })

  describe('remove member', () => {
    it('shows remove button for each member', async () => {
      mockGroupMembersSuccess([
        makeGroupMember({ user_id: 'u1' }),
        makeGroupMember({ user_id: 'u2' }),
      ])
      mockOrgMembersSuccess([])
      await mountDialog()
      await flushPromises()

      const removeBtns = findAllTestId('remove-group-member-btn')
      expect(removeBtns.length).toBe(2)
    })

    it('calls DELETE and removes member from list', async () => {
      mockGroupMembersSuccess([
        makeGroupMember({ user_id: 'u1', display_name: 'Alice', email: 'alice@example.com' }),
        makeGroupMember({ user_id: 'u2', display_name: 'Bob', email: 'bob@example.com' }),
      ])
      mockOrgMembersSuccess([
        makeOrgMember({ user_id: 'u1', email: 'alice@example.com' }),
        makeOrgMember({ user_id: 'u2', email: 'bob@example.com' }),
      ])
      await mountDialog()
      await flushPromises()

      mockFetch.mockReset()
      mockRemoveMemberSuccess()

      // Remove the second member (Bob)
      const removeBtns = findAllTestId('remove-group-member-btn')
      removeBtns[1]!.click()
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/groups/${TEST_GROUP_ID}/members/u2`,
        expect.objectContaining({
          method: 'DELETE',
          credentials: 'include',
          headers: expect.objectContaining({
            'X-Requested-By': 'CVErt-Ops',
          }),
        }),
      )

      expect(bodyText()).toContain('alice@example.com')
      expect(bodyText()).not.toContain('bob@example.com')
    })
  })

  describe('add member', () => {
    it('shows available org members not already in group', async () => {
      mockGroupMembersSuccess([
        makeGroupMember({ user_id: 'u1', email: 'alice@example.com' }),
      ])
      mockOrgMembersSuccess([
        makeOrgMember({ user_id: 'u1', email: 'alice@example.com' }),
        makeOrgMember({ user_id: 'u2', email: 'bob@example.com', display_name: 'Bob' }),
        makeOrgMember({ user_id: 'u3', email: 'carol@example.com', display_name: 'Carol' }),
      ])
      await mountDialog()
      await flushPromises()

      // Access the component's computed property for available members
      const vm = wrapper.vm as any
      const available = vm.availableMembers
      expect(available.length).toBe(2)
      expect(available.map((m: any) => m.email)).toEqual(['bob@example.com', 'carol@example.com'])
    })

    it('calls POST to add a member and updates the list', async () => {
      mockGroupMembersSuccess([])
      mockOrgMembersSuccess([
        makeOrgMember({ user_id: 'u1', email: 'alice@example.com', display_name: 'Alice' }),
      ])
      await mountDialog()
      await flushPromises()

      mockFetch.mockReset()
      mockAddMemberSuccess()

      // Use the exposed addMember method since reka-ui Select is hard to trigger in JSDOM
      const vm = wrapper.vm as any
      await vm.addMember('u1')
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/groups/${TEST_GROUP_ID}/members`,
        expect.objectContaining({
          method: 'POST',
          credentials: 'include',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-Requested-By': 'CVErt-Ops',
          }),
          body: JSON.stringify({ user_id: 'u1' }),
        }),
      )

      // Member should now appear in the members list
      expect(bodyText()).toContain('alice@example.com')
    })
  })

  describe('API integration', () => {
    it('fetches group members with correct URL', async () => {
      mockGroupMembersSuccess([])
      mockOrgMembersSuccess([])
      await mountDialog()
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/groups/${TEST_GROUP_ID}/members`,
        expect.objectContaining({
          method: 'GET',
          credentials: 'include',
        }),
      )
    })

    it('fetches org members with correct URL', async () => {
      mockGroupMembersSuccess([])
      mockOrgMembersSuccess([])
      await mountDialog()
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/members`,
        expect.objectContaining({
          method: 'GET',
          credentials: 'include',
        }),
      )
    })
  })
})
