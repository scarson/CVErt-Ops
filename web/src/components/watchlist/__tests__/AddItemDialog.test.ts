// ABOUTME: Tests for the add watchlist item dialog component.
// ABOUTME: Covers package/CPE item type selection, form validation, API submission, and error handling.

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
const TEST_WATCHLIST_ID = 'wl-123'

function makePackageItem(overrides: Record<string, unknown> = {}) {
  return {
    id: 'item-001',
    item_type: 'package',
    ecosystem: 'npm',
    package_name: 'lodash',
    namespace: undefined,
    cpe_normalized: undefined,
    created_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

function makeCpeItem(overrides: Record<string, unknown> = {}) {
  return {
    id: 'item-002',
    item_type: 'cpe',
    ecosystem: undefined,
    package_name: undefined,
    namespace: undefined,
    cpe_normalized: 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
    created_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

function mockAddSuccess(item: Record<string, unknown> = makePackageItem()) {
  mockPOST.mockResolvedValueOnce({
    data: item,
    error: undefined,
  })
}

function mockAddConflict() {
  mockPOST.mockResolvedValueOnce({
    data: undefined,
    error: { status: 409, detail: 'item already exists in watchlist' },
  })
}

function mockAddValidationError() {
  mockPOST.mockResolvedValueOnce({
    data: undefined,
    error: { status: 422, detail: 'package_name is required for package items' },
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

// reka-ui Select is hard to interact with in JSDOM, so we call the
// exposed selectEcosystem method directly (same pattern as MembersView tests).
async function selectEcosystem(value: string) {
  const vm = wrapper.vm as any
  vm.selectEcosystem(value)
  await flushPromises()
}

async function clickTestId(testId: string) {
  const el = findTestId(testId)
  el?.click()
}

let wrapper: VueWrapper

async function mountDialog(open = true) {
  const { default: AddItemDialog } = await import('@/components/watchlist/AddItemDialog.vue')
  wrapper = mount(AddItemDialog, {
    props: { open, watchlistId: TEST_WATCHLIST_ID },
    attachTo: document.body,
  })
  return wrapper
}

describe('AddItemDialog', () => {
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

  it('renders item type selector', async () => {
    await mountDialog()
    await flushPromises()

    const packageBtn = findTestId('item-type-package')
    const cpeBtn = findTestId('item-type-cpe')
    expect(packageBtn).not.toBeNull()
    expect(cpeBtn).not.toBeNull()
  })

  it('shows package fields by default', async () => {
    await mountDialog()
    await flushPromises()

    expect(findTestId('ecosystem-select-trigger')).not.toBeNull()
    expect(findTestId('package-name-input')).not.toBeNull()
    expect(findTestId('namespace-input')).not.toBeNull()
  })

  it('shows CPE field when CPE type is selected', async () => {
    await mountDialog()
    await flushPromises()

    await clickTestId('item-type-cpe')
    await flushPromises()

    expect(findTestId('cpe-input')).not.toBeNull()
    // Package fields should be hidden
    expect(findTestId('package-name-input')).toBeNull()
  })

  it('has add button disabled when required fields are empty', async () => {
    await mountDialog()
    await flushPromises()

    const btn = findTestId('add-item-btn') as HTMLButtonElement
    expect(btn).not.toBeNull()
    expect(btn.disabled).toBe(true)
  })

  it('submits package item correctly', async () => {
    const item = makePackageItem()
    mockAddSuccess(item)

    await mountDialog()
    await flushPromises()

    // Select ecosystem via native select
    await selectEcosystem('npm')
    await flushPromises()

    // Fill package name
    await setInputValue('package-name-input', 'lodash')
    await flushPromises()

    await clickTestId('add-item-btn')
    await flushPromises()

    expect(mockPOST).toHaveBeenCalledWith(
      '/orgs/{org_id}/watchlists/{id}/items',
      expect.objectContaining({
        params: { path: { org_id: TEST_ORG_ID, id: TEST_WATCHLIST_ID } },
        body: expect.objectContaining({
          item_type: 'package',
          ecosystem: 'npm',
          package_name: 'lodash',
        }),
      }),
    )
  })

  it('submits CPE item correctly', async () => {
    const item = makeCpeItem()
    mockAddSuccess(item)

    await mountDialog()
    await flushPromises()

    // Switch to CPE
    await clickTestId('item-type-cpe')
    await flushPromises()

    // Fill CPE
    await setInputValue('cpe-input', 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*')
    await flushPromises()

    await clickTestId('add-item-btn')
    await flushPromises()

    expect(mockPOST).toHaveBeenCalledWith(
      '/orgs/{org_id}/watchlists/{id}/items',
      expect.objectContaining({
        params: { path: { org_id: TEST_ORG_ID, id: TEST_WATCHLIST_ID } },
        body: expect.objectContaining({
          item_type: 'cpe',
          cpe_normalized: 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
        }),
      }),
    )
  })

  it('shows error on 409 duplicate', async () => {
    mockAddConflict()

    await mountDialog()
    await flushPromises()

    await selectEcosystem('npm')
    await flushPromises()

    await setInputValue('package-name-input', 'lodash')
    await flushPromises()

    await clickTestId('add-item-btn')
    await flushPromises()

    const errorEl = findTestId('add-item-error')
    expect(errorEl).not.toBeNull()
    expect(errorEl?.textContent).toContain('item already exists in watchlist')
  })

  it('shows error on 422 validation', async () => {
    mockAddValidationError()

    await mountDialog()
    await flushPromises()

    await selectEcosystem('npm')
    await flushPromises()

    await setInputValue('package-name-input', 'something')
    await flushPromises()

    await clickTestId('add-item-btn')
    await flushPromises()

    const errorEl = findTestId('add-item-error')
    expect(errorEl).not.toBeNull()
    expect(errorEl?.textContent).toContain('package_name is required')
  })

  it('emits added event on success', async () => {
    const item = makePackageItem()
    mockAddSuccess(item)

    await mountDialog()
    await flushPromises()

    await selectEcosystem('npm')
    await flushPromises()

    await setInputValue('package-name-input', 'lodash')
    await flushPromises()

    await clickTestId('add-item-btn')
    await flushPromises()

    expect(wrapper.emitted('added')).toBeTruthy()
    expect(wrapper.emitted('added')![0]).toEqual([item])
  })

  it('closes dialog on success', async () => {
    const item = makePackageItem()
    mockAddSuccess(item)

    await mountDialog()
    await flushPromises()

    await selectEcosystem('npm')
    await flushPromises()

    await setInputValue('package-name-input', 'lodash')
    await flushPromises()

    await clickTestId('add-item-btn')
    await flushPromises()

    expect(wrapper.emitted('update:open')).toBeTruthy()
    const openEvents = wrapper.emitted('update:open')!
    const lastEvent = openEvents[openEvents.length - 1]
    expect(lastEvent).toEqual([false])
  })
})
