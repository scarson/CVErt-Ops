// ABOUTME: Tests for the groups management page view.
// ABOUTME: Covers group listing, create/edit/delete flows, member management, RBAC visibility, and states.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises, VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'

const mockPush = vi.fn()

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ params: {} })),
  useRouter: vi.fn(() => ({ push: mockPush })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000001'
const TEST_USER_ID = '00000000-0000-0000-0000-000000000099'

function makeGroup(overrides: Record<string, unknown> = {}) {
  return {
    id: 'grp-001',
    name: 'Engineering',
    description: 'Dev team',
    created_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

function mockGroupsSuccess(groups = [makeGroup()]) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 200,
    json: () => Promise.resolve(groups),
  })
}

function mockGroupsError() {
  mockFetch.mockResolvedValueOnce({
    ok: false,
    status: 500,
    json: () => Promise.resolve({ detail: 'Internal Server Error' }),
  })
}

function mockDeleteSuccess() {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 204,
    json: () => Promise.resolve(null),
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

let wrapper: VueWrapper

async function mountView() {
  const { default: GroupsView } = await import('@/views/GroupsView.vue')
  wrapper = mount(GroupsView, {
    attachTo: document.body,
  })
  return wrapper
}

// Clean up portaled DOM elements (reka-ui Select, AlertDialog, Dialog)
function cleanupPortals() {
  document.querySelectorAll('[data-reka-portal], [data-radix-popper-content-wrapper]').forEach((el) => el.remove())
}

describe('GroupsView', () => {
  beforeEach(() => {
    const pinia = createPinia()
    setActivePinia(pinia)
    vi.clearAllMocks()
    mockFetch.mockReset()
  })

  afterEach(() => {
    wrapper?.unmount()
    cleanupPortals()
  })

  describe('loading state', () => {
    it('shows loading indicator while fetching', async () => {
      setupAuthStore('admin')
      mockFetch.mockImplementation(() => new Promise(() => {}))
      await mountView()

      expect(wrapper.text()).toContain('Loading')
    })
  })

  describe('error state', () => {
    it('shows error message on fetch failure', async () => {
      setupAuthStore('admin')
      mockGroupsError()
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to load groups')
    })
  })

  describe('rendering with data', () => {
    it('renders page title and subtitle', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess()
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Groups')
      expect(wrapper.text()).toContain('Organize members into groups')
    })

    it('renders groups table with data', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([
        makeGroup({ id: 'g1', name: 'Engineering', description: 'Dev team' }),
        makeGroup({ id: 'g2', name: 'Security', description: 'Security team' }),
      ])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Engineering')
      expect(wrapper.text()).toContain('Security')
      expect(wrapper.text()).toContain('Dev team')
      expect(wrapper.text()).toContain('Security team')
    })

    it('formats created date', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([makeGroup({ created_at: '2025-06-15T00:00:00Z' })])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Jun')
      expect(wrapper.text()).toContain('2025')
    })
  })

  describe('empty state', () => {
    it('renders empty state when no groups', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('No groups yet')
    })

    it('shows create button in empty state for admin', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([])
      await mountView()
      await flushPromises()

      const createBtn = wrapper.find('[data-testid="empty-create-group-btn"]')
      expect(createBtn.exists()).toBe(true)
    })
  })

  describe('RBAC: new group button visibility', () => {
    it('shows New Group button for admin users', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess()
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="new-group-btn"]')
      expect(btn.exists()).toBe(true)
    })

    it('shows New Group button for owner users', async () => {
      setupAuthStore('owner')
      mockGroupsSuccess()
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="new-group-btn"]')
      expect(btn.exists()).toBe(true)
    })

    it('hides New Group button for member users', async () => {
      setupAuthStore('member')
      mockGroupsSuccess()
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="new-group-btn"]')
      expect(btn.exists()).toBe(false)
    })

    it('hides New Group button for viewer users', async () => {
      setupAuthStore('viewer')
      mockGroupsSuccess()
      await mountView()
      await flushPromises()

      const btn = wrapper.find('[data-testid="new-group-btn"]')
      expect(btn.exists()).toBe(false)
    })
  })

  describe('RBAC: action buttons visibility', () => {
    it('shows edit/delete/members buttons for admin users', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([makeGroup()])
      await mountView()
      await flushPromises()

      expect(wrapper.find('[data-testid="edit-group-btn"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="delete-group-btn"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="manage-members-btn"]').exists()).toBe(true)
    })

    it('hides edit/delete/members buttons for viewer users', async () => {
      setupAuthStore('viewer')
      mockGroupsSuccess([makeGroup()])
      await mountView()
      await flushPromises()

      expect(wrapper.find('[data-testid="edit-group-btn"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="delete-group-btn"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="manage-members-btn"]').exists()).toBe(false)
    })
  })

  describe('create flow', () => {
    it('opens dialog when New Group is clicked', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([])
      await mountView()
      await flushPromises()

      await wrapper.find('[data-testid="empty-create-group-btn"]').trigger('click')
      await flushPromises()

      const nameInput = findTestId('group-name-input')
      expect(nameInput).not.toBeNull()
    })

    it('adds group to list after creation', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([])
      await mountView()
      await flushPromises()

      const newEntry = makeGroup({ id: 'grp-new', name: 'New Team' })

      // Open dialog
      await wrapper.find('[data-testid="empty-create-group-btn"]').trigger('click')
      await flushPromises()

      // Simulate the dialog emitting saved
      const dialog = wrapper.findComponent({ name: 'GroupDialog' })
      expect(dialog.exists()).toBe(true)
      dialog.vm.$emit('saved', newEntry)
      await flushPromises()

      expect(wrapper.text()).toContain('New Team')
    })
  })

  describe('edit flow', () => {
    it('opens dialog pre-filled when edit is clicked', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([makeGroup({ name: 'Engineering', description: 'Dev team' })])
      await mountView()
      await flushPromises()

      await wrapper.find('[data-testid="edit-group-btn"]').trigger('click')
      await flushPromises()

      const nameInput = findTestId('group-name-input') as HTMLInputElement
      expect(nameInput).not.toBeNull()
      expect(nameInput.value).toBe('Engineering')
    })

    it('updates group in list after edit', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([makeGroup({ id: 'grp-1', name: 'Old Name' })])
      await mountView()
      await flushPromises()

      await wrapper.find('[data-testid="edit-group-btn"]').trigger('click')
      await flushPromises()

      const updatedEntry = makeGroup({ id: 'grp-1', name: 'Updated Name' })

      const dialog = wrapper.findComponent({ name: 'GroupDialog' })
      dialog.vm.$emit('saved', updatedEntry)
      await flushPromises()

      expect(wrapper.text()).toContain('Updated Name')
      expect(wrapper.text()).not.toContain('Old Name')
    })
  })

  describe('delete flow', () => {
    it('shows confirmation dialog when delete is clicked', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([makeGroup()])
      await mountView()
      await flushPromises()

      await wrapper.find('[data-testid="delete-group-btn"]').trigger('click')
      await flushPromises()

      expect(bodyText()).toContain('Are you sure')
      expect(bodyText()).toContain('permanently delete')
    })

    it('calls DELETE on confirmation and removes from list', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([
        makeGroup({ id: 'g1', name: 'Keep' }),
        makeGroup({ id: 'g2', name: 'Delete Me' }),
      ])
      await mountView()
      await flushPromises()

      mockFetch.mockReset()
      mockDeleteSuccess()

      // Click delete on second group
      const deleteBtns = wrapper.findAll('[data-testid="delete-group-btn"]')
      expect(deleteBtns.length).toBe(2)
      await deleteBtns[1]!.trigger('click')
      await flushPromises()

      // Confirm via portal button
      const confirmBtn = findTestId('confirm-delete-group-btn')
      expect(confirmBtn).not.toBeNull()
      confirmBtn!.click()
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/groups/g2`,
        expect.objectContaining({
          method: 'DELETE',
          credentials: 'include',
          headers: expect.objectContaining({
            'X-Requested-By': 'CVErt-Ops',
          }),
        }),
      )

      expect(wrapper.text()).toContain('Keep')
      expect(wrapper.text()).not.toContain('Delete Me')
    })
  })

  describe('manage members flow', () => {
    it('opens members dialog when manage members is clicked', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess([makeGroup({ name: 'Engineering' })])
      await mountView()
      await flushPromises()

      // Mock the fetches that GroupMembersDialog will make when it opens
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([]),
      })
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve([]),
      })

      await wrapper.find('[data-testid="manage-members-btn"]').trigger('click')
      await flushPromises()

      // The GroupMembersDialog should be open — check for its content
      expect(bodyText()).toContain('Engineering')
      expect(bodyText()).toContain('Members')
    })
  })

  describe('API integration', () => {
    it('fetches groups with correct URL and options', async () => {
      setupAuthStore('admin')
      mockGroupsSuccess()
      await mountView()
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/groups`,
        expect.objectContaining({
          method: 'GET',
          credentials: 'include',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        }),
      )
    })
  })
})
