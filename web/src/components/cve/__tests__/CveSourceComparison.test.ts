// ABOUTME: Tests for the CveSourceComparison tabbed component.
// ABOUTME: Covers tab rendering, source data display, loading, and empty states.

import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import type { components } from '@/lib/api/schema'

type CVESourceResponse = components['schemas']['CVESourceResponse']

vi.mock('vue-router', () => ({
  useRoute: vi.fn<() => unknown>(() => ({ query: {} })),
  useRouter: vi.fn<() => unknown>(() => ({ push: vi.fn<(...args: unknown[]) => unknown>() })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

function makeSource(overrides: Partial<CVESourceResponse> = {}): CVESourceResponse {
  return {
    source_name: 'nvd',
    ingested_at: '2024-12-15T10:30:00Z',
    source_date_modified: '2024-12-14T08:00:00Z',
    source_id: 'CVE-2024-12345',
    source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345',
    normalized_json: {
      description: 'Test description from NVD',
      cvss_v3_score: 9.8,
      severity: 'critical',
    },
    ...overrides,
  }
}

async function mountComponent(props: Record<string, unknown> = {}) {
  const { default: CveSourceComparison } = await import('@/components/cve/CveSourceComparison.vue')
  return mount(CveSourceComparison, { props: props as any })
}

describe('CveSourceComparison', () => {
  describe('rendering', () => {
    it('renders a tab for each source', async () => {
      const sources = [
        makeSource({ source_name: 'nvd' }),
        makeSource({ source_name: 'mitre' }),
        makeSource({ source_name: 'ghsa' }),
      ]
      const wrapper = await mountComponent({ sources, loading: false })

      expect(wrapper.text()).toContain('NVD')
      expect(wrapper.text()).toContain('MITRE')
      expect(wrapper.text()).toContain('GHSA')
    })

    it('shows source metadata for the active tab', async () => {
      const sources = [
        makeSource({
          source_name: 'nvd',
          source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345',
          ingested_at: '2024-12-15T10:30:00Z',
        }),
      ]
      const wrapper = await mountComponent({ sources, loading: false })

      expect(wrapper.text()).toContain('nvd.nist.gov')
    })

    it('renders normalized_json content', async () => {
      const sources = [
        makeSource({
          source_name: 'nvd',
          normalized_json: {
            description: 'A test vulnerability description',
            cvss_v3_score: 7.5,
          },
        }),
      ]
      const wrapper = await mountComponent({ sources, loading: false })

      expect(wrapper.text()).toContain('description')
      expect(wrapper.text()).toContain('A test vulnerability description')
    })
  })

  describe('source name formatting', () => {
    it('uppercases known source names', async () => {
      const sources = [makeSource({ source_name: 'nvd' })]
      const wrapper = await mountComponent({ sources, loading: false })

      expect(wrapper.text()).toContain('NVD')
    })

    it('capitalizes unknown source names', async () => {
      const sources = [makeSource({ source_name: 'custom-feed' })]
      const wrapper = await mountComponent({ sources, loading: false })

      expect(wrapper.text()).toContain('Custom-feed')
    })
  })

  describe('states', () => {
    it('shows loading state', async () => {
      const wrapper = await mountComponent({ sources: [], loading: true })

      expect(wrapper.text()).toContain('Loading')
    })

    it('shows empty state when no sources', async () => {
      const wrapper = await mountComponent({ sources: [], loading: false })

      expect(wrapper.text()).toContain('No source data available')
    })
  })
})
