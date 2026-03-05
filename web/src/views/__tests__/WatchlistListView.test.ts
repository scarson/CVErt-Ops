// ABOUTME: Tests for the watchlist list view page.
// ABOUTME: Covers data fetching, table rendering, create/delete flows, and error states.

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

function makeWatchlist(overrides: Record<string, unknown> = {}) {
  return {
    id: 'wl-001',
    name: 'Production Dependencies',
    description: 'Tracks production packages',
    item_count: 12,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-15T10:30:00Z',
    ...overrides,
  }
}

function mockListSuccess(items = [makeWatchlist()], nextCursor?: string) {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 200,
    json: () => Promise.resolve({ items, next_cursor: nextCursor }),
  })
}

function mockListError() {
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
// We use attachTo: document.body and query the DOM directly for portaled content.
function findTestId(id: string): HTMLElement | null {
  return document.querySelector(`[data-testid="${id}"]`)
}

function findAllTestId(id: string): NodeListOf<HTMLElement> {
  return document.querySelectorAll(`[data-testid="${id}"]`)
}

function bodyText(): string {
  return document.body.textContent ?? ''
}

let wrapper: VueWrapper

async function mountView() {
  const { default: WatchlistListView } = await import('@/views/WatchlistListView.vue')
  wrapper = mount(WatchlistListView, {
    attachTo: document.body,
  })
  return wrapper
}

describe('WatchlistListView', () => {
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

  describe('loading state', () => {
    it('shows loading indicator while fetching', async () => {
      mockFetch.mockImplementation(() => new Promise(() => {}))
      await mountView()

      expect(wrapper.text()).toContain('Loading')
    })
  })

  describe('rendering with data', () => {
    it('renders page title and subtitle', async () => {
      mockListSuccess()
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Watchlists')
      expect(wrapper.text()).toContain('Track packages and products')
    })

    it('renders watchlists table with data', async () => {
      mockListSuccess([
        makeWatchlist({ id: 'wl-1', name: 'Prod Deps', description: 'Production', item_count: 5 }),
        makeWatchlist({ id: 'wl-2', name: 'Dev Tools', description: 'Development', item_count: 3 }),
      ])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Prod Deps')
      expect(wrapper.text()).toContain('Dev Tools')
    })

    it('displays item counts', async () => {
      mockListSuccess([makeWatchlist({ item_count: 42 })])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('42')
    })

    it('renders watchlist name as link to detail page', async () => {
      mockListSuccess([makeWatchlist({ id: 'wl-abc', name: 'My List' })])
      await mountView()
      await flushPromises()

      const link = wrapper.find('a[href="/watchlists/wl-abc"]')
      expect(link.exists()).toBe(true)
      expect(link.text()).toContain('My List')
    })

    it('truncates long descriptions', async () => {
      const longDesc = 'A'.repeat(200)
      mockListSuccess([makeWatchlist({ description: longDesc })])
      await mountView()
      await flushPromises()

      const descCell = wrapper.find('[data-testid="watchlist-description"]')
      expect(descCell.exists()).toBe(true)
      const text = descCell.text()
      expect(text.length).toBeLessThan(200)
    })
  })

  describe('empty state', () => {
    it('renders empty state when no watchlists', async () => {
      mockListSuccess([])
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('No watchlists yet')
      expect(wrapper.text()).toContain('Create your first watchlist')
    })

    it('shows create button in empty state', async () => {
      mockListSuccess([])
      await mountView()
      await flushPromises()

      const createBtn = wrapper.find('[data-testid="empty-create-btn"]')
      expect(createBtn.exists()).toBe(true)
    })
  })

  describe('error state', () => {
    it('shows error message on fetch failure', async () => {
      mockListError()
      await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to load watchlists')
    })
  })

  describe('create flow', () => {
    it('has a New Watchlist button', async () => {
      mockListSuccess()
      await mountView()
      await flushPromises()

      const newBtn = wrapper.find('[data-testid="new-watchlist-btn"]')
      expect(newBtn.exists()).toBe(true)
      expect(newBtn.text()).toContain('New Watchlist')
    })

    it('opens create dialog when New Watchlist is clicked', async () => {
      mockListSuccess()
      await mountView()
      await flushPromises()

      await wrapper.find('[data-testid="new-watchlist-btn"]').trigger('click')
      await flushPromises()

      // Dialog content is rendered via portal to body
      const nameInput = findTestId('watchlist-name-input')
      expect(nameInput).not.toBeNull()
    })

    it('adds watchlist to list after creation', async () => {
      mockListSuccess([])
      await mountView()
      await flushPromises()

      const newEntry = makeWatchlist({ id: 'wl-new', name: 'Brand New' })

      // Open dialog
      await wrapper.find('[data-testid="empty-create-btn"]').trigger('click')
      await flushPromises()

      // Simulate the dialog emitting created
      const dialog = wrapper.findComponent({ name: 'CreateWatchlistDialog' })
      expect(dialog.exists()).toBe(true)
      dialog.vm.$emit('created', newEntry)
      await flushPromises()

      expect(wrapper.text()).toContain('Brand New')
    })
  })

  describe('delete flow', () => {
    it('shows delete button per row', async () => {
      mockListSuccess([makeWatchlist()])
      await mountView()
      await flushPromises()

      const deleteBtn = wrapper.find('[data-testid="delete-watchlist-btn"]')
      expect(deleteBtn.exists()).toBe(true)
    })

    it('shows confirmation dialog when delete is clicked', async () => {
      mockListSuccess([makeWatchlist()])
      await mountView()
      await flushPromises()

      await wrapper.find('[data-testid="delete-watchlist-btn"]').trigger('click')
      await flushPromises()

      // AlertDialog content is portaled to body
      expect(bodyText()).toContain('Are you sure')
      expect(bodyText()).toContain('permanently delete')
    })

    it('calls DELETE endpoint on confirmation', async () => {
      mockListSuccess([makeWatchlist({ id: 'wl-del' })])
      await mountView()
      await flushPromises()

      mockFetch.mockClear()
      mockDeleteSuccess()

      await wrapper.find('[data-testid="delete-watchlist-btn"]').trigger('click')
      await flushPromises()

      // Confirm button is in the portal
      const confirmBtn = findTestId('confirm-delete-btn')
      expect(confirmBtn).not.toBeNull()
      confirmBtn!.click()
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/watchlists/wl-del`,
        expect.objectContaining({
          method: 'DELETE',
          credentials: 'include',
          headers: expect.objectContaining({
            'X-Requested-By': 'CVErt-Ops',
          }),
        }),
      )
    })

    it('removes watchlist from list after successful delete', async () => {
      mockListSuccess([
        makeWatchlist({ id: 'wl-1', name: 'Keep Me' }),
        makeWatchlist({ id: 'wl-2', name: 'Delete Me' }),
      ])
      await mountView()
      await flushPromises()

      mockFetch.mockClear()
      mockDeleteSuccess()

      // Click delete on second row
      const deleteBtns = wrapper.findAll('[data-testid="delete-watchlist-btn"]')
      expect(deleteBtns.length).toBe(2)
      await deleteBtns[1]!.trigger('click')
      await flushPromises()

      // Confirm via portal button
      const confirmBtn = findTestId('confirm-delete-btn')
      expect(confirmBtn).not.toBeNull()
      confirmBtn!.click()
      await flushPromises()

      expect(wrapper.text()).toContain('Keep Me')
      expect(wrapper.text()).not.toContain('Delete Me')
    })
  })

  describe('API integration', () => {
    it('fetches watchlists with correct URL and options', async () => {
      mockListSuccess()
      await mountView()
      await flushPromises()

      expect(mockFetch).toHaveBeenCalledWith(
        `/api/v1/orgs/${TEST_ORG_ID}/watchlists`,
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
