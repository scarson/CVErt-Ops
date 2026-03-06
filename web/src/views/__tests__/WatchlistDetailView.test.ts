// ABOUTME: Tests for the watchlist detail view page.
// ABOUTME: Covers loading, 404, inline editing, items table, add/remove item flows.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises, VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'

let mockRouteParams: Record<string, string> = { id: 'wl-123' }
const mockPush = vi.fn()

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ params: mockRouteParams })),
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

function makeWatchlist(overrides: Record<string, unknown> = {}) {
  return {
    id: 'wl-123',
    name: 'Production Deps',
    description: 'Tracks production packages',
    item_count: 3,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-15T10:30:00Z',
    ...overrides,
  }
}

function makePackageItem(overrides: Record<string, unknown> = {}) {
  return {
    id: 'item-001',
    item_type: 'package',
    ecosystem: 'npm',
    package_name: 'lodash',
    namespace: undefined,
    cpe_normalized: undefined,
    created_at: '2025-01-10T00:00:00Z',
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
    cpe_normalized: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
    created_at: '2025-01-12T00:00:00Z',
    ...overrides,
  }
}

function mockWatchlistSuccess(wl = makeWatchlist()) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 200,
    json: () => Promise.resolve(wl),
  })
}

function mockWatchlistNotFound() {
  mockFetch.mockResolvedValueOnce({
    ok: false,
    status: 404,
    json: () => Promise.resolve({ detail: 'watchlist not found' }),
  })
}

function mockItemsSuccess(items: unknown[] = [], nextCursor?: string) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 200,
    json: () => Promise.resolve({ items, next_cursor: nextCursor }),
  })
}

function mockPatchSuccess(wl = makeWatchlist()) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 200,
    json: () => Promise.resolve(wl),
  })
}

function mockDeleteItemSuccess() {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 204,
    json: () => Promise.resolve(null),
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

async function mountView() {
  const { default: WatchlistDetailView } = await import(
    '@/views/WatchlistDetailView.vue'
  )
  wrapper = mount(WatchlistDetailView, {
    attachTo: document.body,
  })
  return wrapper
}

describe('WatchlistDetailView', () => {
  beforeEach(() => {
    const pinia = createPinia()
    setActivePinia(pinia)
    vi.clearAllMocks()
    mockRouteParams = { id: 'wl-123' }

    const auth = useAuthStore()
    auth.activeOrgId = TEST_ORG_ID
  })

  afterEach(() => {
    wrapper?.unmount()
  })

  describe('loading state', () => {
    it('shows loading indicator while fetching', async () => {
      mockFetch.mockImplementation(() => new Promise(() => {}))
      await mountView()

      expect(wrapper.text()).toContain('Loading')
    })
  })

  describe('404 state', () => {
    it('shows not found message when watchlist returns 404', async () => {
      mockWatchlistNotFound()
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Watchlist not found')
    })
  })

  describe('error state', () => {
    it('shows error message when API returns 500', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: () => Promise.resolve({ detail: 'Internal Server Error' }),
      })
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to load watchlist')
    })

    it('shows error when fetching items fails (network error)', async () => {
      mockWatchlistSuccess()
      mockFetch.mockRejectedValueOnce(new Error('Network error'))

      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to load items')
    })
  })

  describe('rendering with data', () => {
    it('renders watchlist name and description', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([makePackageItem()])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Production Deps')
      expect(wrapper.text()).toContain('Tracks production packages')
    })

    it('renders items table with package items', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([
        makePackageItem({ id: 'p1', ecosystem: 'npm', package_name: 'lodash' }),
        makePackageItem({ id: 'p2', ecosystem: 'pypi', package_name: 'requests' }),
      ])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('npm/lodash')
      expect(wrapper.text()).toContain('pypi/requests')
    })

    it('renders items table with CPE items', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([
        makeCpeItem({
          id: 'c1',
          cpe_normalized: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
        }),
      ])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('cpe:2.3:a:apache:log4j')
    })

    it('renders empty items state', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('No items in this watchlist')
      expect(wrapper.text()).toContain('Add packages or CPE patterns to monitor')
    })

    it('has back link to watchlists', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([])
      await mountView()
      await flushPromises()

      const backLink = wrapper.find('a[href="/watchlists"]')
      expect(backLink.exists()).toBe(true)
    })
  })

  describe('accessibility', () => {
    it('has accessible labels on icon-only action buttons', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([makePackageItem()])
      await mountView()
      await flushPromises()

      const editBtn = findTestId('edit-name-btn')
      expect(editBtn!.getAttribute('aria-label')).toBe('Edit watchlist name')

      const deleteItemBtn = findTestId('delete-item-btn')
      expect(deleteItemBtn!.getAttribute('aria-label')).toBe('Remove item')
    })

    it('has accessible labels on inline edit buttons', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([])
      await mountView()
      await flushPromises()

      await clickTestId('edit-name-btn')
      await flushPromises()

      const saveBtn = findTestId('save-name-btn')
      expect(saveBtn!.getAttribute('aria-label')).toBe('Save name')

      const cancelBtn = findTestId('cancel-name-btn')
      expect(cancelBtn!.getAttribute('aria-label')).toBe('Cancel editing')
    })
  })

  describe('edit mode', () => {
    it('clicking name switches to edit input', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([])
      await mountView()
      await flushPromises()

      await clickTestId('edit-name-btn')
      await flushPromises()

      const input = findTestId('edit-name-input') as HTMLInputElement
      expect(input).not.toBeNull()
      expect(input.value).toBe('Production Deps')
    })

    it('provides accessible labels for inline edit inputs', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([])
      await mountView()
      await flushPromises()

      // Enter edit mode
      await clickTestId('edit-name-btn')
      await flushPromises()

      const nameInput = findTestId('edit-name-input')
      expect(nameInput).not.toBeNull()
      expect(nameInput!.getAttribute('aria-label')).toBe('Watchlist name')

      const descInput = findTestId('edit-description-input')
      expect(descInput).not.toBeNull()
      expect(descInput!.getAttribute('aria-label')).toBe('Watchlist description')
    })

    it('save calls PATCH and updates display', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([])
      await mountView()
      await flushPromises()

      // Enter edit mode
      await clickTestId('edit-name-btn')
      await flushPromises()

      // Change name
      await setInputValue('edit-name-input', 'Updated Name')
      await flushPromises()

      // Mock PATCH response
      mockPatchSuccess(makeWatchlist({ name: 'Updated Name' }))

      // Save
      await clickTestId('save-name-btn')
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/watchlists/wl-123`,
        expect.objectContaining({
          method: 'PATCH',
        }),
      )

      // Verify the name was updated in the display
      expect(wrapper.text()).toContain('Updated Name')
    })
  })

  describe('edit mode error handling', () => {
    it('shows error and keeps original name when save PATCH fails', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([])
      await mountView()
      await flushPromises()

      // Enter edit mode
      await clickTestId('edit-name-btn')
      await flushPromises()

      // Change name
      await setInputValue('edit-name-input', 'New Name')
      await flushPromises()

      // Mock failed PATCH
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: () => Promise.resolve({ detail: 'Server error' }),
      })

      await clickTestId('save-name-btn')
      await flushPromises()

      // Should show error
      expect(wrapper.text()).toContain('Failed to save')
      // Original name should still be displayed after exiting edit mode
      expect(wrapper.text()).toContain('Production Deps')
    })
  })

  describe('delete item', () => {
    it('calls DELETE endpoint and removes item from list', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([
        makePackageItem({ id: 'item-keep', package_name: 'kept-pkg' }),
        makePackageItem({ id: 'item-del', package_name: 'deleted-pkg' }),
      ])
      await mountView()
      await flushPromises()

      mockFetch.mockClear()
      mockDeleteItemSuccess()

      // Click delete on the second item
      const deleteBtns = wrapper.findAll('[data-testid="delete-item-btn"]')
      expect(deleteBtns.length).toBe(2)
      await deleteBtns[1]!.trigger('click')
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/watchlists/wl-123/items/item-del`,
        expect.objectContaining({
          method: 'DELETE',
        }),
      )

      expect(wrapper.text()).toContain('kept-pkg')
      expect(wrapper.text()).not.toContain('deleted-pkg')
    })

    it('shows error and keeps item when DELETE fails', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([makePackageItem({ id: 'item-1', package_name: 'survivor-pkg' })])
      await mountView()
      await flushPromises()

      mockFetch.mockClear()
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: () => Promise.resolve({ detail: 'Server error' }),
      })

      const deleteBtn = wrapper.find('[data-testid="delete-item-btn"]')
      await deleteBtn.trigger('click')
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to delete item')
      expect(wrapper.text()).toContain('survivor-pkg')
    })
  })

  describe('add item flow', () => {
    it('clicking Add Item opens dialog', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([])
      await mountView()
      await flushPromises()

      await wrapper.find('[data-testid="add-item-btn-trigger"]').trigger('click')
      await flushPromises()

      // Dialog content is in portal
      expect(findTestId('item-type-package')).not.toBeNull()
    })

    it('adds item to list after dialog emits added', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([])
      await mountView()
      await flushPromises()

      // Open dialog
      await wrapper.find('[data-testid="add-item-btn-trigger"]').trigger('click')
      await flushPromises()

      // Simulate AddItemDialog emitting 'added'
      const dialog = wrapper.findComponent({ name: 'AddItemDialog' })
      expect(dialog.exists()).toBe(true)

      const newItem = makePackageItem({ id: 'item-new', package_name: 'express' })
      dialog.vm.$emit('added', newItem)
      await flushPromises()

      expect(wrapper.text()).toContain('npm/express')
    })
  })

  describe('org switch navigation', () => {
    it('navigates to /watchlists when activeOrgId changes', async () => {
      const auth = useAuthStore()
      auth.activeOrgId = TEST_ORG_ID
      mockWatchlistSuccess()
      mockItemsSuccess([makePackageItem()])
      await mountView()
      await flushPromises()

      mockPush.mockClear()
      auth.activeOrgId = '00000000-0000-0000-0000-000000000002'
      await flushPromises()

      expect(mockPush).toHaveBeenCalledWith('/watchlists')
    })
  })

  describe('API integration', () => {
    it('fetches watchlist and items with correct URLs', async () => {
      mockWatchlistSuccess()
      mockItemsSuccess([makePackageItem()])
      await mountView()
      await flushPromises()

      // First call: fetch watchlist
      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/watchlists/wl-123`,
        expect.objectContaining({
          method: 'GET',
        }),
      )

      // Second call: fetch items
      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/watchlists/wl-123/items`,
        expect.objectContaining({
          method: 'GET',
        }),
      )
    })
  })
})
