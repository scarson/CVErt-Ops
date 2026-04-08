// ABOUTME: Tests for the invite member dialog component.
// ABOUTME: Covers form rendering, role restrictions, submission, success state, and event emission.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises, VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'

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

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn<(...args: unknown[]) => unknown>(),
    POST: (...args: unknown[]) => mockPOST(...args),
    PATCH: vi.fn<(...args: unknown[]) => unknown>(),
    DELETE: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000001'

function makeInvitationEntry(overrides: Record<string, unknown> = {}) {
  return {
    id: 'inv-001',
    email: 'newuser@example.com',
    role: 'member',
    expires_at: '2025-01-08T00:00:00Z',
    created_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

function mockInviteSuccess(entry = makeInvitationEntry()) {
  mockPOST.mockResolvedValueOnce({
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

async function mountDialog(props: { open?: boolean; currentUserRole?: string } = {}) {
  const { default: InviteMemberDialog } =
    await import('@/components/settings/InviteMemberDialog.vue')
  wrapper = mount(InviteMemberDialog, {
    props: { open: true, currentUserRole: 'admin', ...props },
    attachTo: document.body,
  })
  return wrapper
}

describe('InviteMemberDialog', () => {
  beforeEach(() => {
    const pinia = createPinia()
    setActivePinia(pinia)
    vi.clearAllMocks()
    mockPOST.mockReset()

    const auth = useAuthStore()
    auth.activeOrgId = TEST_ORG_ID
  })

  afterEach(() => {
    wrapper?.unmount()
  })

  it('renders email input and role select', async () => {
    await mountDialog()
    await flushPromises()

    expect(findTestId('invite-email-input')).not.toBeNull()
    expect(findTestId('invite-role-trigger')).not.toBeNull()
  })

  describe('role options limited by currentUserRole', () => {
    it('owner can invite admin, member, viewer', async () => {
      await mountDialog({ currentUserRole: 'owner' })
      await flushPromises()

      // Access computed availableRoles via component instance
      const vm = wrapper.vm as any
      expect(vm.availableRoles).toEqual(['admin', 'member', 'viewer'])
    })

    it('admin can invite member and viewer only', async () => {
      await mountDialog({ currentUserRole: 'admin' })
      await flushPromises()

      const vm = wrapper.vm as any
      expect(vm.availableRoles).toEqual(['member', 'viewer'])
    })
  })

  it('send button disabled when email is empty', async () => {
    await mountDialog()
    await flushPromises()

    const btn = findTestId('send-invite-btn') as HTMLButtonElement
    expect(btn).not.toBeNull()
    expect(btn.disabled).toBe(true)
  })

  it('send button enabled when email has a value', async () => {
    await mountDialog()
    await flushPromises()

    await setInputValue('invite-email-input', 'user@example.com')
    await flushPromises()

    const btn = findTestId('send-invite-btn') as HTMLButtonElement
    expect(btn.disabled).toBe(false)
  })

  it('submits invitation correctly', async () => {
    const entry = makeInvitationEntry({ email: 'test@example.com', role: 'member' })
    mockInviteSuccess(entry)

    await mountDialog()
    await flushPromises()

    await setInputValue('invite-email-input', 'test@example.com')
    await flushPromises()

    await clickTestId('send-invite-btn')
    await flushPromises()

    expect(mockPOST).toHaveBeenCalledWith(
      '/orgs/{org_id}/invitations',
      expect.objectContaining({
        params: { path: { org_id: TEST_ORG_ID } },
        body: { email: 'test@example.com', role: 'member' },
      }),
    )
  })

  it('shows success message after success', async () => {
    mockInviteSuccess()

    await mountDialog()
    await flushPromises()

    await setInputValue('invite-email-input', 'newuser@example.com')
    await flushPromises()

    await clickTestId('send-invite-btn')
    await flushPromises()

    const successMsg = findTestId('invite-success')
    expect(successMsg).not.toBeNull()
    expect(successMsg!.textContent).toContain('Invitation sent')
  })

  it('emits invited event on success', async () => {
    const entry = makeInvitationEntry()
    mockInviteSuccess(entry)

    await mountDialog()
    await flushPromises()

    await setInputValue('invite-email-input', 'newuser@example.com')
    await flushPromises()

    await clickTestId('send-invite-btn')
    await flushPromises()

    expect(wrapper.emitted('invited')).toBeTruthy()
    expect(wrapper.emitted('invited')![0]).toEqual([entry])
  })

  it('resets form when dialog closes and reopens', async () => {
    mockInviteSuccess()

    await mountDialog()
    await flushPromises()

    await setInputValue('invite-email-input', 'user@example.com')
    await flushPromises()

    await clickTestId('send-invite-btn')
    await flushPromises()

    // Close the dialog
    await wrapper.setProps({ open: false })
    await flushPromises()

    // Reopen
    await wrapper.setProps({ open: true })
    await flushPromises()

    const emailInput = getInput('invite-email-input')
    expect(emailInput.value).toBe('')
    expect(findTestId('invite-success')).toBeNull()
  })
})
