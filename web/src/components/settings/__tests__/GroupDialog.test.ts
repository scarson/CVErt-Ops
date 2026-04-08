// ABOUTME: Tests for the group create/edit dialog component.
// ABOUTME: Covers create mode, edit mode, form validation, API calls, and event emission.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises, VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import type { GroupEntry } from '@/components/settings/GroupDialog.vue'

vi.mock('vue-router', () => ({
  useRoute: vi.fn<() => unknown>(() => ({ params: {} })),
  useRouter: vi.fn<() => unknown>(() => ({ push: vi.fn<(...args: unknown[]) => unknown>() })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

const mockPOST = vi.fn<(...args: unknown[]) => unknown>()
const mockPATCH = vi.fn<(...args: unknown[]) => unknown>()

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn<(...args: unknown[]) => unknown>(),
    POST: (...args: unknown[]) => mockPOST(...args),
    PATCH: (...args: unknown[]) => mockPATCH(...args),
    DELETE: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000001'

function makeGroup(overrides: Record<string, unknown> = {}) {
  return {
    id: 'grp-001',
    name: 'Engineering',
    description: 'Dev team',
    created_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

function mockCreateSuccess(entry = makeGroup()) {
  mockPOST.mockResolvedValueOnce({
    data: entry,
    error: undefined,
  })
}

function mockPatchSuccess(entry = makeGroup()) {
  mockPATCH.mockResolvedValueOnce({
    data: entry,
    error: undefined,
  })
}

// Dialog content renders inside a portal (teleported to body).
function findTestId(id: string): HTMLElement | null {
  return document.querySelector(`[data-testid="${id}"]`)
}

function getInput(testId: string): HTMLInputElement {
  return findTestId(testId) as HTMLInputElement
}

async function setInputValue(testId: string, value: string) {
  const input = getInput(testId)
  const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    'value',
  )?.set
  nativeInputValueSetter?.call(input, value)
  input.dispatchEvent(new Event('input', { bubbles: true }))
}

async function clickTestId(testId: string) {
  const el = findTestId(testId)
  el?.click()
}

let wrapper: VueWrapper

async function mountDialog(props: { open?: boolean; group?: GroupEntry | null } = {}) {
  const { default: GroupDialog } = await import('@/components/settings/GroupDialog.vue')
  wrapper = mount(GroupDialog, {
    props: { open: true, group: null, ...props },
    attachTo: document.body,
  })
  return wrapper
}

describe('GroupDialog', () => {
  beforeEach(() => {
    const pinia = createPinia()
    setActivePinia(pinia)
    vi.clearAllMocks()
    mockPOST.mockReset()
    mockPATCH.mockReset()

    const auth = useAuthStore()
    auth.activeOrgId = TEST_ORG_ID
  })

  afterEach(() => {
    wrapper?.unmount()
  })

  describe('create mode', () => {
    it('renders empty name and description fields', async () => {
      await mountDialog()
      await flushPromises()

      const nameInput = getInput('group-name-input')
      const descInput = getInput('group-description-input')
      expect(nameInput).not.toBeNull()
      expect(descInput).not.toBeNull()
      expect(nameInput.value).toBe('')
      expect(descInput.value).toBe('')
    })

    it('shows "Create" button text', async () => {
      await mountDialog()
      await flushPromises()

      const btn = findTestId('group-submit-btn')
      expect(btn).not.toBeNull()
      expect(btn!.textContent).toContain('Create')
    })

    it('submit button disabled when name is empty', async () => {
      await mountDialog()
      await flushPromises()

      const btn = findTestId('group-submit-btn') as HTMLButtonElement
      expect(btn.disabled).toBe(true)
    })

    it('submit button enabled when name has value', async () => {
      await mountDialog()
      await flushPromises()

      await setInputValue('group-name-input', 'New Group')
      await flushPromises()

      const btn = findTestId('group-submit-btn') as HTMLButtonElement
      expect(btn.disabled).toBe(false)
    })

    it('calls POST to create a group', async () => {
      const entry = makeGroup({ name: 'New Group', description: 'A new group' })
      mockCreateSuccess(entry)

      await mountDialog()
      await flushPromises()

      await setInputValue('group-name-input', 'New Group')
      await setInputValue('group-description-input', 'A new group')
      await flushPromises()

      await clickTestId('group-submit-btn')
      await flushPromises()

      expect(mockPOST).toHaveBeenCalledWith(
        '/orgs/{org_id}/groups',
        expect.objectContaining({
          params: { path: { org_id: TEST_ORG_ID } },
          body: { name: 'New Group', description: 'A new group' },
        }),
      )
    })

    it('emits saved with group entry on success', async () => {
      const entry = makeGroup({ name: 'New Group' })
      mockCreateSuccess(entry)

      await mountDialog()
      await flushPromises()

      await setInputValue('group-name-input', 'New Group')
      await flushPromises()

      await clickTestId('group-submit-btn')
      await flushPromises()

      expect(wrapper.emitted('saved')).toBeTruthy()
      expect(wrapper.emitted('saved')![0]).toEqual([entry])
    })
  })

  describe('edit mode', () => {
    it('pre-fills name and description', async () => {
      await mountDialog({ group: makeGroup({ name: 'Existing', description: 'A team' }) })
      await flushPromises()

      const nameInput = getInput('group-name-input')
      const descInput = getInput('group-description-input')
      expect(nameInput.value).toBe('Existing')
      expect(descInput.value).toBe('A team')
    })

    it('shows "Save" button text', async () => {
      await mountDialog({ group: makeGroup() })
      await flushPromises()

      const btn = findTestId('group-submit-btn')
      expect(btn).not.toBeNull()
      expect(btn!.textContent).toContain('Save')
    })

    it('calls PATCH to update a group', async () => {
      const existing = makeGroup({ id: 'grp-edit', name: 'Old Name', description: 'Old desc' })
      const updated = { ...existing, name: 'Updated Name', description: 'Updated desc' }
      mockPatchSuccess(updated)

      await mountDialog({ group: existing })
      await flushPromises()

      await setInputValue('group-name-input', 'Updated Name')
      await setInputValue('group-description-input', 'Updated desc')
      await flushPromises()

      await clickTestId('group-submit-btn')
      await flushPromises()

      expect(mockPATCH).toHaveBeenCalledWith(
        '/orgs/{org_id}/groups/{group_id}',
        expect.objectContaining({
          params: { path: { org_id: TEST_ORG_ID, group_id: 'grp-edit' } },
          body: { name: 'Updated Name', description: 'Updated desc' },
        }),
      )
    })

    it('emits saved with updated entry on success', async () => {
      const existing = makeGroup({ id: 'grp-edit', name: 'Old' })
      const updated = { ...existing, name: 'New' }
      mockPatchSuccess(updated)

      await mountDialog({ group: existing })
      await flushPromises()

      await setInputValue('group-name-input', 'New')
      await flushPromises()

      await clickTestId('group-submit-btn')
      await flushPromises()

      expect(wrapper.emitted('saved')).toBeTruthy()
      expect(wrapper.emitted('saved')![0]).toEqual([updated])
    })
  })

  describe('form reset', () => {
    it('resets form when dialog closes and reopens', async () => {
      await mountDialog()
      await flushPromises()

      await setInputValue('group-name-input', 'Temp Name')
      await flushPromises()

      // Close the dialog
      await wrapper.setProps({ open: false })
      await flushPromises()

      // Reopen in create mode
      await wrapper.setProps({ open: true, group: null })
      await flushPromises()

      const nameInput = getInput('group-name-input')
      expect(nameInput.value).toBe('')
    })
  })
})
