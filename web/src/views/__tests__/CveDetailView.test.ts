// ABOUTME: Tests for the CVE detail view page.
// ABOUTME: Covers API integration, score cards, references, affected products, 404 handling, and loading states.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { components } from '@/lib/api/schema'

type CVEDetail = components['schemas']['CVEDetail']
type CVESourceResponse = components['schemas']['CVESourceResponse']

let mockRouteParams: Record<string, string> = {}

vi.mock('vue-router', () => ({
  useRoute: vi.fn<() => { params: Record<string, string>; query: Record<string, unknown> }>(() => ({
    params: mockRouteParams,
    query: {},
  })),
  useRouter: vi.fn<
    () => { push: (...args: unknown[]) => unknown; back: (...args: unknown[]) => unknown }
  >(() => ({
    push: vi.fn<(...args: unknown[]) => unknown>(),
    back: vi.fn<(...args: unknown[]) => unknown>(),
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

function makeCVEDetail(overrides: Partial<CVEDetail> = {}): CVEDetail {
  return {
    cve_id: 'CVE-2024-12345',
    description_primary: 'A critical vulnerability in Apache Log4j allows remote code execution.',
    cvss_v3_score: 9.8,
    cvss_v3_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cvss_v4_score: undefined,
    cvss_v4_vector: undefined,
    epss_score: 0.975,
    severity: 'critical',
    status: 'Published',
    date_modified: '2024-12-15T10:30:00Z',
    date_published: '2024-12-01T00:00:00Z',
    date_first_seen: '2024-12-01T00:00:00Z',
    cwe_ids: ['CWE-502', 'CWE-917'],
    exploit_available: true,
    in_cisa_kev: true,
    cvss_score_diverges: false,
    affected_cpes: [
      { cpe: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*', cpe_normalized: 'apache log4j 2.14.1' },
    ],
    affected_packages: [
      {
        ecosystem: 'Maven',
        package_name: 'org.apache.logging.log4j:log4j-core',
        introduced: '2.0',
        fixed: '2.17.1',
        range_type: 'SEMVER',
      },
    ],
    references: [
      { url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345', tags: ['third-party-advisory'] },
      { url: 'https://github.com/advisories/GHSA-xxxx-xxxx-xxxx', tags: ['patch'] },
    ],
    ...overrides,
  }
}

function makeSources(overrides: Partial<CVESourceResponse>[] = []): CVESourceResponse[] {
  const defaults: CVESourceResponse[] = [
    {
      source_name: 'nvd',
      ingested_at: '2024-12-15T10:30:00Z',
      source_date_modified: '2024-12-14T08:00:00Z',
      source_id: 'CVE-2024-12345',
      source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345',
      normalized_json: { description: 'NVD description', cvss_v3_score: 9.8 },
    },
    {
      source_name: 'mitre',
      ingested_at: '2024-12-15T09:00:00Z',
      source_date_modified: '2024-12-13T08:00:00Z',
      source_id: 'CVE-2024-12345',
      source_url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345',
      normalized_json: { description: 'MITRE description' },
    },
  ]
  if (overrides.length > 0) {
    return overrides.map((o, i) => ({ ...defaults[i % defaults.length]!, ...o }))
  }
  return defaults
}

function mockCveResponse(detail: CVEDetail) {
  mockGET.mockImplementation((path: string) => {
    if (path === '/cves/{cve_id}') {
      return Promise.resolve({ data: detail, error: undefined })
    }
    if (path === '/cves/{cve_id}/sources') {
      return Promise.resolve({
        data: { sources: makeSources() },
        error: undefined,
      })
    }
    return Promise.resolve({ data: undefined, error: { status: 404 } })
  })
}

function mock404Response() {
  mockGET.mockImplementation(() =>
    Promise.resolve({
      data: undefined,
      error: { type: 'about:blank', title: 'Not Found', status: 404 },
    }),
  )
}

function mockErrorResponse() {
  mockGET.mockImplementation(() =>
    Promise.resolve({
      data: undefined,
      error: { type: 'about:blank', title: 'Internal Server Error', status: 500 },
    }),
  )
}

async function mountView() {
  const { default: CveDetailView } = await import('@/views/CveDetailView.vue')
  return mount(CveDetailView)
}

describe('CveDetailView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    mockRouteParams = { cveId: 'CVE-2024-12345' }
    mockCveResponse(makeCVEDetail())
  })

  describe('header', () => {
    it('displays the CVE ID as page title', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('CVE-2024-12345')
    })

    it('displays the status badge', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Published')
    })

    it('displays published and modified dates', async () => {
      const wrapper = await mountView()
      await flushPromises()

      // Should contain formatted dates (year check)
      expect(wrapper.text()).toContain('2024')
    })
  })

  describe('score cards', () => {
    it('displays CVSS score', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('9.8')
    })

    it('displays EPSS score as percentage', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('97.5%')
    })

    it('displays KEV status', async () => {
      const wrapper = await mountView()
      await flushPromises()

      // CVE is in KEV, should show "Yes"
      const text = wrapper.text()
      expect(text).toContain('KEV')
      expect(text).toContain('Yes')
    })

    it('shows N/A for missing CVSS score', async () => {
      mockCveResponse(makeCVEDetail({ cvss_v3_score: undefined, cvss_v4_score: undefined }))
      const wrapper = await mountView()
      await flushPromises()

      const scoreCards = wrapper.findAll('[data-testid="score-card"]')
      const cvssCard = scoreCards.find((c) => c.text().includes('CVSS'))
      expect(cvssCard?.text()).toContain('N/A')
    })

    it('shows N/A for missing EPSS score', async () => {
      mockCveResponse(makeCVEDetail({ epss_score: undefined }))
      const wrapper = await mountView()
      await flushPromises()

      const scoreCards = wrapper.findAll('[data-testid="score-card"]')
      const epssCard = scoreCards.find((c) => c.text().includes('EPSS'))
      expect(epssCard?.text()).toContain('N/A')
    })

    it('shows exploit availability', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Exploit')
    })
  })

  describe('description', () => {
    it('displays the full CVE description', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('A critical vulnerability in Apache Log4j')
    })

    it('shows placeholder when no description', async () => {
      mockCveResponse(makeCVEDetail({ description_primary: undefined }))
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('No description available')
    })
  })

  describe('CWE IDs', () => {
    it('displays CWE IDs', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('CWE-502')
      expect(wrapper.text()).toContain('CWE-917')
    })
  })

  describe('affected products', () => {
    it('displays affected packages', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('org.apache.logging.log4j:log4j-core')
      expect(wrapper.text()).toContain('Maven')
    })

    it('displays affected CPEs', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('apache log4j 2.14.1')
    })

    it('shows empty state when no affected products', async () => {
      mockCveResponse(makeCVEDetail({ affected_packages: null, affected_cpes: null }))
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('No affected products listed')
    })
  })

  describe('references', () => {
    it('displays reference URLs as links', async () => {
      const wrapper = await mountView()
      await flushPromises()

      const links = wrapper.findAll('a[target="_blank"]')
      const urls = links.map((l) => l.attributes('href'))
      expect(urls).toContain('https://nvd.nist.gov/vuln/detail/CVE-2024-12345')
      expect(urls).toContain('https://github.com/advisories/GHSA-xxxx-xxxx-xxxx')
    })

    it('shows reference tags as badges', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('third-party-advisory')
      expect(wrapper.text()).toContain('patch')
    })

    it('shows empty state when no references', async () => {
      mockCveResponse(makeCVEDetail({ references: null }))
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('No references listed')
    })
  })

  describe('source comparison', () => {
    it('fetches sources from the API', async () => {
      await mountView()
      await flushPromises()

      expect(mockGET).toHaveBeenCalledWith(
        '/cves/{cve_id}/sources',
        expect.objectContaining({
          params: { path: { cve_id: 'CVE-2024-12345' } },
        }),
      )
    })

    it('renders source tabs', async () => {
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('NVD')
      expect(wrapper.text()).toContain('MITRE')
    })
  })

  describe('loading state', () => {
    it('shows loading indicator while fetching', async () => {
      // Don't resolve the promises immediately
      mockGET.mockImplementation(
        () => new Promise(() => {}), // Never resolves
      )
      const wrapper = await mountView()

      expect(wrapper.text()).toContain('Loading')
    })
  })

  describe('404 handling', () => {
    it('shows not found message when CVE does not exist', async () => {
      mock404Response()
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('CVE not found')
    })
  })

  describe('error handling', () => {
    it('shows error message on API failure', async () => {
      mockErrorResponse()
      const wrapper = await mountView()
      await flushPromises()

      expect(wrapper.text()).toContain('Failed to load CVE')
    })
  })

  describe('stale response protection', () => {
    it('discards stale response when fetchCve is called again before previous resolves', async () => {
      // Mount with initial data
      mockGET.mockResolvedValueOnce({ data: makeCVEDetail({ cve_id: 'CVE-2024-12345' }) })
      mockGET.mockResolvedValueOnce({ data: { sources: makeSources() }, error: undefined })

      const { default: CveDetailView } = await import('@/views/CveDetailView.vue')
      const wrapper = mount(CveDetailView)
      await flushPromises()

      expect(wrapper.text()).toContain('CVE-2024-12345')

      // Set up a slow response (will become stale)
      let resolveStale: (v: unknown) => void
      const stalePromise = new Promise((resolve) => {
        resolveStale = resolve
      })
      mockGET.mockReturnValueOnce(stalePromise)

      // Trigger first refetch — increments fetchId
      const vm = wrapper.vm as any
      vm.fetchCve()

      // Before it resolves, trigger another refetch — increments fetchId again
      mockGET.mockResolvedValueOnce({
        data: makeCVEDetail({ cve_id: 'CVE-2024-12345', description_primary: 'Fresh data' }),
      })
      vm.fetchCve()
      await flushPromises()

      // Fresh data should be showing
      expect(wrapper.text()).toContain('Fresh data')

      // Now resolve the stale promise
      resolveStale!({
        data: makeCVEDetail({ cve_id: 'CVE-2024-12345', description_primary: 'Stale data' }),
      })
      await flushPromises()

      // Should still show fresh data, not stale
      expect(wrapper.text()).toContain('Fresh data')
      expect(wrapper.text()).not.toContain('Stale data')
    })
  })

  describe('back navigation', () => {
    it('renders a back link to search results', async () => {
      const wrapper = await mountView()
      await flushPromises()

      const backLink = wrapper.find('[data-testid="back-link"]')
      expect(backLink.exists()).toBe(true)
    })
  })

  describe('API integration', () => {
    it('fetches CVE detail with correct path params', async () => {
      await mountView()
      await flushPromises()

      expect(mockGET).toHaveBeenCalledWith(
        '/cves/{cve_id}',
        expect.objectContaining({
          params: { path: { cve_id: 'CVE-2024-12345' } },
        }),
      )
    })

    it('uses cveId from route params', async () => {
      mockRouteParams = { cveId: 'CVE-2025-99999' }
      mockCveResponse(makeCVEDetail({ cve_id: 'CVE-2025-99999' }))

      const wrapper = await mountView()
      await flushPromises()

      expect(mockGET).toHaveBeenCalledWith(
        '/cves/{cve_id}',
        expect.objectContaining({
          params: { path: { cve_id: 'CVE-2025-99999' } },
        }),
      )
      expect(wrapper.text()).toContain('CVE-2025-99999')
    })
  })
})
