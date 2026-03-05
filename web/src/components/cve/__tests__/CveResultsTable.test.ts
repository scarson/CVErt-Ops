// ABOUTME: Tests for the CVE results table component.
// ABOUTME: Covers column rendering, score badges, description truncation, and empty/loading states.

import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import type { components } from '@/lib/api/schema'

type CVEItem = components['schemas']['CVEItem']

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ query: {} })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

function makeCVE(overrides: Partial<CVEItem> = {}): CVEItem {
  return {
    cve_id: 'CVE-2024-12345',
    description_primary: 'A critical vulnerability in Apache Log4j allows remote code execution via crafted log messages.',
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

async function mountTable(props = {}) {
  const { default: CveResultsTable } = await import('@/components/cve/CveResultsTable.vue')
  return mount(CveResultsTable, {
    props: {
      items: [],
      loading: false,
      ...props,
    },
  })
}

describe('CveResultsTable', () => {
  describe('rendering', () => {
    it('renders table headers', async () => {
      const wrapper = await mountTable()

      const text = wrapper.text()
      expect(text).toContain('CVE ID')
      expect(text).toContain('Description')
      expect(text).toContain('CVSS')
      expect(text).toContain('EPSS')
      expect(text).toContain('Modified')
    })

    it('renders CVE rows with data', async () => {
      const items = [makeCVE()]
      const wrapper = await mountTable({ items })

      const text = wrapper.text()
      expect(text).toContain('CVE-2024-12345')
      expect(text).toContain('9.8')
    })

    it('renders CVE ID as a link to detail page', async () => {
      const items = [makeCVE()]
      const wrapper = await mountTable({ items })

      const link = wrapper.find('a[href="/cves/CVE-2024-12345"]')
      expect(link.exists()).toBe(true)
    })

    it('truncates long descriptions', async () => {
      const longDesc = 'A'.repeat(200)
      const items = [makeCVE({ description_primary: longDesc })]
      const wrapper = await mountTable({ items })

      // The displayed text should be truncated (not the full 200 chars)
      const descCell = wrapper.text()
      // Should not contain the full 200-char string
      expect(descCell).not.toContain(longDesc)
    })

    it('renders multiple rows', async () => {
      const items = [
        makeCVE({ cve_id: 'CVE-2024-0001' }),
        makeCVE({ cve_id: 'CVE-2024-0002' }),
        makeCVE({ cve_id: 'CVE-2024-0003' }),
      ]
      const wrapper = await mountTable({ items })

      expect(wrapper.text()).toContain('CVE-2024-0001')
      expect(wrapper.text()).toContain('CVE-2024-0002')
      expect(wrapper.text()).toContain('CVE-2024-0003')
    })
  })

  describe('severity badges', () => {
    it('renders a badge for critical severity', async () => {
      const items = [makeCVE({ severity: 'critical', cvss_v3_score: 9.8 })]
      const wrapper = await mountTable({ items })

      const badge = wrapper.find('[data-testid="cvss-badge"]')
      expect(badge.exists()).toBe(true)
      expect(badge.text()).toContain('9.8')
    })

    it('shows N/A when no CVSS score is available', async () => {
      const items = [makeCVE({ cvss_v3_score: undefined, severity: undefined })]
      const wrapper = await mountTable({ items })

      const badge = wrapper.find('[data-testid="cvss-badge"]')
      expect(badge.text()).toContain('N/A')
    })
  })

  describe('EPSS score', () => {
    it('formats EPSS as percentage', async () => {
      const items = [makeCVE({ epss_score: 0.975 })]
      const wrapper = await mountTable({ items })

      expect(wrapper.text()).toContain('97.5%')
    })

    it('shows dash when no EPSS score', async () => {
      const items = [makeCVE({ epss_score: undefined })]
      const wrapper = await mountTable({ items })

      const cells = wrapper.findAll('td')
      const epssCell = cells.find(c => c.text() === '\u2014')
      expect(epssCell).toBeDefined()
    })
  })

  describe('states', () => {
    it('shows empty state when no items and not loading', async () => {
      const wrapper = await mountTable({ items: [], loading: false })

      expect(wrapper.text()).toContain('No CVEs found matching your search')
    })

    it('shows loading state', async () => {
      const wrapper = await mountTable({ items: [], loading: true })

      expect(wrapper.text()).toContain('Loading')
    })

    it('does not show empty state when loading', async () => {
      const wrapper = await mountTable({ items: [], loading: true })

      expect(wrapper.text()).not.toContain('No CVEs found matching your search')
    })
  })

  describe('date formatting', () => {
    it('formats the modified date', async () => {
      const items = [makeCVE({ date_modified: '2024-12-15T10:30:00Z' })]
      const wrapper = await mountTable({ items })

      // Should contain a formatted date string (locale-dependent, check for year)
      expect(wrapper.text()).toContain('2024')
    })
  })
})
