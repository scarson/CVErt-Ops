// ABOUTME: Tests for the CVE search view page.
// ABOUTME: Covers API integration, URL state sync, pagination, loading/error states.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { components } from '@/lib/api/schema'

type CVEItem = components['schemas']['CVEItem']

const mockPush = vi.fn<(...args: unknown[]) => unknown>()
const mockReplace = vi.fn<(...args: unknown[]) => unknown>()
let mockRouteQuery: Record<string, string | undefined> = {}

vi.mock('vue-router', () => ({
  useRoute: vi.fn<() => { query: Record<string, string | undefined> }>(() => ({
    query: mockRouteQuery,
  })),
  useRouter: vi.fn<() => { push: typeof mockPush; replace: typeof mockReplace }>(() => ({
    push: mockPush,
    replace: mockReplace,
  })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

const mockGET = vi.fn<(...args: unknown[]) => unknown>()

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: (...args: unknown[]) => mockGET(...args),
    POST: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

function makeCVE(overrides: Partial<CVEItem> = {}): CVEItem {
  return {
    cve_id: 'CVE-2024-12345',
    description_primary: 'Test vulnerability description',
    cvss_v3_score: 9.8,
    epss_score: 0.975,
    severity: 'critical',
    date_modified: '2024-12-15T10:30:00Z',
    date_published: '2024-12-01T00:00:00Z',
    date_first_seen: '2024-12-01T00:00:00Z',
    cwe_ids: ['CWE-502'],
    exploit_available: false,
    in_cisa_kev: false,
    cvss_score_diverges: false,
    ...overrides,
  }
}

function mockSuccessResponse(items: CVEItem[], nextCursor?: string) {
  mockGET.mockResolvedValue({
    data: {
      items,
      next_cursor: nextCursor,
    },
    error: undefined,
  })
}

function mockErrorResponse() {
  mockGET.mockResolvedValue({
    data: undefined,
    error: {
      type: 'about:blank',
      title: 'Internal Server Error',
      status: 500,
    },
  })
}

async function mountView() {
  const { default: CveSearchView } = await import('@/views/CveSearchView.vue')
  return mount(CveSearchView)
}

describe('CveSearchView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    mockRouteQuery = {}
    mockSuccessResponse([])
  })

  describe('rendering', () => {
    it('renders the page title', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('CVE Search')
    })

    it('renders the search filters', async () => {
      const wrapper = await mountView()
      await flushPromises()

      const searchInput = wrapper.find('input[type="search"]')
      expect(searchInput.exists()).toBe(true)
    })

    it('renders the results table', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('CVE ID')
      expect(wrapper.text()).toContain('Description')
    })
  })

  describe('API integration', () => {
    it('fetches CVEs on mount', async () => {
      mockSuccessResponse([makeCVE()])
      await mountView()
      await flushPromises()

      expect(mockGET).toHaveBeenCalledWith(
        '/cves',
        expect.objectContaining({
          params: expect.objectContaining({
            query: expect.any(Object),
          }),
        }),
      )
    })

    it('displays fetched CVE results', async () => {
      mockSuccessResponse([
        makeCVE({ cve_id: 'CVE-2024-0001' }),
        makeCVE({ cve_id: 'CVE-2024-0002' }),
      ])
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('CVE-2024-0001')
      expect(wrapper.text()).toContain('CVE-2024-0002')
    })

    it('passes search query to API', async () => {
      mockRouteQuery = { q: 'apache' }
      mockSuccessResponse([])
      await mountView()
      await flushPromises()

      expect(mockGET).toHaveBeenCalledWith(
        '/cves',
        expect.objectContaining({
          params: {
            query: expect.objectContaining({
              q: 'apache',
            }),
          },
        }),
      )
    })

    it('passes severity filter to API', async () => {
      mockRouteQuery = { severity: 'critical' }
      mockSuccessResponse([])
      await mountView()
      await flushPromises()

      expect(mockGET).toHaveBeenCalledWith(
        '/cves',
        expect.objectContaining({
          params: {
            query: expect.objectContaining({
              severity: ['critical'],
            }),
          },
        }),
      )
    })
  })

  describe('search behavior', () => {
    it('performs search when filters emit search event', async () => {
      mockSuccessResponse([])
      const wrapper = await mountView()
      await flushPromises()

      mockGET.mockClear()
      mockSuccessResponse([makeCVE({ cve_id: 'CVE-2024-9999' })])

      await wrapper.find('input[type="search"]').setValue('log4j')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(mockGET).toHaveBeenCalled()
      expect(wrapper.text()).toContain('CVE-2024-9999')
    })

    it('updates URL query params on search', async () => {
      mockSuccessResponse([])
      const wrapper = await mountView()
      await flushPromises()

      await wrapper.find('input[type="search"]').setValue('openssl')
      await wrapper.find('form').trigger('submit')
      await flushPromises()

      expect(mockReplace).toHaveBeenCalledWith(
        expect.objectContaining({
          query: expect.objectContaining({
            q: 'openssl',
          }),
        }),
      )
    })
  })

  describe('pagination', () => {
    it('shows Next button when next_cursor is present', async () => {
      mockSuccessResponse([makeCVE()], 'cursor-page2')
      const wrapper = await mountView()
      await flushPromises()

      const nextButton = wrapper.find('[data-testid="next-page"]')
      expect(nextButton.exists()).toBe(true)
      expect(nextButton.attributes('disabled')).toBeUndefined()
    })

    it('disables Next button when no next_cursor', async () => {
      mockSuccessResponse([makeCVE()])
      const wrapper = await mountView()
      await flushPromises()

      const nextButton = wrapper.find('[data-testid="next-page"]')
      expect(nextButton.exists()).toBe(true)
      expect(nextButton.attributes('disabled')).toBeDefined()
    })

    it('disables Previous button on first page', async () => {
      mockSuccessResponse([makeCVE()])
      const wrapper = await mountView()
      await flushPromises()

      const prevButton = wrapper.find('[data-testid="prev-page"]')
      expect(prevButton.exists()).toBe(true)
      expect(prevButton.attributes('disabled')).toBeDefined()
    })

    it('navigates to next page when Next is clicked', async () => {
      mockSuccessResponse([makeCVE({ cve_id: 'CVE-2024-0001' })], 'cursor-page2')
      const wrapper = await mountView()
      await flushPromises()

      mockGET.mockClear()
      mockSuccessResponse([makeCVE({ cve_id: 'CVE-2024-0002' })], 'cursor-page3')

      await wrapper.find('[data-testid="next-page"]').trigger('click')
      await flushPromises()

      expect(mockGET).toHaveBeenCalledWith(
        '/cves',
        expect.objectContaining({
          params: {
            query: expect.objectContaining({
              cursor: 'cursor-page2',
            }),
          },
        }),
      )
      expect(wrapper.text()).toContain('CVE-2024-0002')
    })

    it('navigates back when Previous is clicked', async () => {
      // First page
      mockSuccessResponse([makeCVE({ cve_id: 'CVE-2024-0001' })], 'cursor-page2')
      const wrapper = await mountView()
      await flushPromises()

      // Go to second page
      mockGET.mockClear()
      mockSuccessResponse([makeCVE({ cve_id: 'CVE-2024-0002' })], 'cursor-page3')
      await wrapper.find('[data-testid="next-page"]').trigger('click')
      await flushPromises()

      // Go back to first page
      mockGET.mockClear()
      mockSuccessResponse([makeCVE({ cve_id: 'CVE-2024-0001' })])
      await wrapper.find('[data-testid="prev-page"]').trigger('click')
      await flushPromises()

      // On first page, cursor should not be in params.
      expect(mockGET).toHaveBeenCalled()
      const callArgs = mockGET.mock.calls[0]![1] as { params: { query: Record<string, unknown> } }
      expect(callArgs.params.query).not.toHaveProperty('cursor')
    })
  })

  describe('error handling', () => {
    it('displays error message on API failure', async () => {
      mockErrorResponse()
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to load CVEs')
    })
  })

  describe('URL state sync', () => {
    it('initializes search from URL query params', async () => {
      mockRouteQuery = { q: 'tomcat', severity: 'high' }
      mockSuccessResponse([])
      const wrapper = await mountView()
      await flushPromises()

      const searchInput = wrapper.find('input[type="search"]')
      expect((searchInput.element as HTMLInputElement).value).toBe('tomcat')
    })
  })
})
