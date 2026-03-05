// ABOUTME: Tests for the CveScoreCard reusable component.
// ABOUTME: Covers label/value rendering, severity coloring, and missing value handling.

import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'

async function mountCard(props: Record<string, unknown> = {}) {
  const { default: CveScoreCard } = await import('@/components/cve/CveScoreCard.vue')
  return mount(CveScoreCard, { props: props as any })
}

describe('CveScoreCard', () => {
  describe('rendering', () => {
    it('renders label and value', async () => {
      const wrapper = await mountCard({ label: 'CVSS', value: '9.8' })

      expect(wrapper.text()).toContain('CVSS')
      expect(wrapper.text()).toContain('9.8')
    })

    it('renders sublabel when provided', async () => {
      const wrapper = await mountCard({
        label: 'CVSS',
        value: '9.8',
        sublabel: 'Critical',
      })

      expect(wrapper.text()).toContain('Critical')
    })

    it('renders fallback when value is undefined', async () => {
      const wrapper = await mountCard({ label: 'CVSS' })

      expect(wrapper.text()).toContain('CVSS')
      expect(wrapper.text()).toContain('N/A')
    })
  })

  describe('severity coloring', () => {
    it('applies critical color class', async () => {
      const wrapper = await mountCard({
        label: 'CVSS',
        value: '9.8',
        severity: 'critical',
      })

      const valueEl = wrapper.find('[data-testid="score-value"]')
      expect(valueEl.classes().some(c => c.includes('red'))).toBe(true)
    })

    it('applies high color class', async () => {
      const wrapper = await mountCard({
        label: 'CVSS',
        value: '7.5',
        severity: 'high',
      })

      const valueEl = wrapper.find('[data-testid="score-value"]')
      expect(valueEl.classes().some(c => c.includes('orange'))).toBe(true)
    })

    it('applies medium color class', async () => {
      const wrapper = await mountCard({
        label: 'CVSS',
        value: '5.0',
        severity: 'medium',
      })

      const valueEl = wrapper.find('[data-testid="score-value"]')
      expect(valueEl.classes().some(c => c.includes('yellow'))).toBe(true)
    })

    it('applies low color class', async () => {
      const wrapper = await mountCard({
        label: 'CVSS',
        value: '2.0',
        severity: 'low',
      })

      const valueEl = wrapper.find('[data-testid="score-value"]')
      expect(valueEl.classes().some(c => c.includes('green'))).toBe(true)
    })

    it('uses default styling when no severity provided', async () => {
      const wrapper = await mountCard({
        label: 'EPSS',
        value: '45.2%',
      })

      const valueEl = wrapper.find('[data-testid="score-value"]')
      expect(valueEl.exists()).toBe(true)
    })
  })

  describe('boolean mode', () => {
    it('shows positive indicator for true boolean values', async () => {
      const wrapper = await mountCard({
        label: 'KEV',
        value: 'Yes',
        severity: 'critical',
      })

      expect(wrapper.text()).toContain('Yes')
    })

    it('shows negative indicator for false boolean values', async () => {
      const wrapper = await mountCard({
        label: 'KEV',
        value: 'No',
      })

      expect(wrapper.text()).toContain('No')
    })
  })
})
