// ABOUTME: Tests for the create watchlist dialog component.
// ABOUTME: Covers form validation, API submission, error handling, and event emission.

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

function makeWatchlistEntry(overrides: Record<string, unknown> = {}) {
  return {
    id: 'wl-001',
    name: 'My Watchlist',
    description: 'Test description',
    item_count: 0,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

function mockCreateSuccess(entry = makeWatchlistEntry()) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 201,
    json: () => Promise.resolve(entry),
  })
}

function mockCreateConflict() {
  mockFetch.mockResolvedValueOnce({
    ok: false,
    status: 409,
    json: () => Promise.resolve({ detail: 'watchlist name already exists' }),
  })
}

function mockCreateForbidden() {
  mockFetch.mockResolvedValueOnce({
    ok: false,
    status: 403,
    json: () => Promise.resolve({ detail: 'tier limit: max watchlists reached' }),
  })
}

// Dialog content renders inside a portal (teleported to body).
// We mount with attachTo: document.body and query the document for elements.
function findTestId(id: string): HTMLElement | null {
  return document.querySelector(`[data-testid="${id}"]`)
}

function getInput(testId: string): HTMLInputElement {
  return findTestId(testId) as HTMLInputElement
}

async function setInputValue(testId: string, value: string) {
  const input = getInput(testId)
  // Trigger native input event so v-model picks it up
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

async function mountDialog(open = true) {
  const { default: CreateWatchlistDialog } = await import(
    '@/components/watchlist/CreateWatchlistDialog.vue'
  )
  wrapper = mount(CreateWatchlistDialog, {
    props: { open },
    attachTo: document.body,
  })
  return wrapper
}

describe('CreateWatchlistDialog', () => {
  beforeEach(() => {
    const pinia = createPinia()
    setActivePinia(pinia)
    vi.clearAllMocks()

    const auth = useAuthStore()
    auth.activeOrgId = TEST_ORG_ID
  })

  afterEach(() => {
    wrapper?.unmount()
  })

  it('renders name and description fields when open', async () => {
    await mountDialog()
    await flushPromises()

    expect(findTestId('watchlist-name-input')).not.toBeNull()
    expect(findTestId('watchlist-description-input')).not.toBeNull()
  })

  it('has create button disabled when name is empty', async () => {
    await mountDialog()
    await flushPromises()

    const btn = findTestId('create-watchlist-btn') as HTMLButtonElement
    expect(btn).not.toBeNull()
    expect(btn.disabled).toBe(true)
  })

  it('enables create button when name has a value', async () => {
    await mountDialog()
    await flushPromises()

    await setInputValue('watchlist-name-input', 'Test Watchlist')
    await flushPromises()

    const btn = findTestId('create-watchlist-btn') as HTMLButtonElement
    expect(btn.disabled).toBe(false)
  })

  it('submits correctly with name and description', async () => {
    const entry = makeWatchlistEntry({ name: 'Test WL', description: 'Desc' })
    mockCreateSuccess(entry)

    await mountDialog()
    await flushPromises()

    await setInputValue('watchlist-name-input', 'Test WL')
    await setInputValue('watchlist-description-input', 'Desc')
    await flushPromises()

    await clickTestId('create-watchlist-btn')
    await flushPromises()

    expect(mockFetch).toHaveBeenCalledWith(
      `/api/v1/orgs/${TEST_ORG_ID}/watchlists`,
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ name: 'Test WL', description: 'Desc' }),
      }),
    )
  })

  it('omits description from payload when empty', async () => {
    mockCreateSuccess(makeWatchlistEntry({ description: undefined }))

    await mountDialog()
    await flushPromises()

    await setInputValue('watchlist-name-input', 'Name Only')
    await flushPromises()

    await clickTestId('create-watchlist-btn')
    await flushPromises()

    const callBody = JSON.parse(mockFetch.mock.calls[0]![1].body as string)
    expect(callBody).toEqual({ name: 'Name Only' })
    expect(callBody).not.toHaveProperty('description')
  })

  it('shows error on 409 conflict', async () => {
    mockCreateConflict()

    await mountDialog()
    await flushPromises()

    await setInputValue('watchlist-name-input', 'Duplicate')
    await flushPromises()

    await clickTestId('create-watchlist-btn')
    await flushPromises()

    const errorEl = findTestId('create-error')
    expect(errorEl?.textContent).toContain('watchlist name already exists')
  })

  it('shows error on 403 tier limit', async () => {
    mockCreateForbidden()

    await mountDialog()
    await flushPromises()

    await setInputValue('watchlist-name-input', 'Too Many')
    await flushPromises()

    await clickTestId('create-watchlist-btn')
    await flushPromises()

    const errorEl = findTestId('create-error')
    expect(errorEl?.textContent).toContain('max watchlists reached')
  })

  it('emits created event on success', async () => {
    const entry = makeWatchlistEntry()
    mockCreateSuccess(entry)

    await mountDialog()
    await flushPromises()

    await setInputValue('watchlist-name-input', 'My Watchlist')
    await flushPromises()

    await clickTestId('create-watchlist-btn')
    await flushPromises()

    expect(wrapper.emitted('created')).toBeTruthy()
    expect(wrapper.emitted('created')![0]).toEqual([entry])
  })

  it('emits update:open with false on success', async () => {
    mockCreateSuccess()

    await mountDialog()
    await flushPromises()

    await setInputValue('watchlist-name-input', 'My Watchlist')
    await flushPromises()

    await clickTestId('create-watchlist-btn')
    await flushPromises()

    expect(wrapper.emitted('update:open')).toBeTruthy()
    const openEvents = wrapper.emitted('update:open')!
    const lastEvent = openEvents[openEvents.length - 1]
    expect(lastEvent).toEqual([false])
  })

  it('resets form fields when dialog closes', async () => {
    mockCreateSuccess()

    await mountDialog()
    await flushPromises()

    await setInputValue('watchlist-name-input', 'My Watchlist')
    await setInputValue('watchlist-description-input', 'Desc')
    await flushPromises()

    // Submit to trigger close (emits update:open false)
    await clickTestId('create-watchlist-btn')
    await flushPromises()

    // Simulate parent responding to update:open by closing the dialog
    await wrapper.setProps({ open: false })
    await flushPromises()

    // Reopen
    await wrapper.setProps({ open: true })
    await flushPromises()

    const nameInput = getInput('watchlist-name-input')
    expect(nameInput.value).toBe('')
  })
})
