// ABOUTME: Tests for the one-time recovery code display.
// ABOUTME: Covers listing, copy, download, the required acknowledgment, and the no-codes warning.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import RecoveryCodesDisplay from '../RecoveryCodesDisplay.vue'

const CODES = ['abcde-12345', 'fghij-67890']

describe('RecoveryCodesDisplay', () => {
  const writeText = vi.fn<(text: string) => Promise<void>>()

  beforeEach(() => {
    writeText.mockReset().mockResolvedValue()
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('lists every code', () => {
    const wrapper = mount(RecoveryCodesDisplay, { props: { codes: CODES } })

    for (const code of CODES) {
      expect(wrapper.text()).toContain(code)
    }
  })

  it('keeps Continue disabled until the user confirms saving the codes', async () => {
    const wrapper = mount(RecoveryCodesDisplay, { props: { codes: CODES } })
    const button = wrapper.find('[data-testid="recovery-codes-done"]')

    expect(button.attributes('disabled')).toBeDefined()
    await wrapper.find('input#recovery-codes-saved').setValue(true)
    expect(button.attributes('disabled')).toBeUndefined()

    await button.trigger('click')
    expect(wrapper.emitted('done')).toHaveLength(1)
  })

  it('copies all codes, one per line', async () => {
    const wrapper = mount(RecoveryCodesDisplay, { props: { codes: CODES } })

    await wrapper.find('[data-testid="copy-recovery-codes"]').trigger('click')

    expect(writeText).toHaveBeenCalledWith('abcde-12345\nfghij-67890')
  })

  it('downloads the codes as a text file', async () => {
    const createObjectURL = vi.fn<(obj: Blob) => string>(() => 'blob:codes')
    const revokeObjectURL = vi.fn<(url: string) => void>()
    Object.assign(URL, { createObjectURL, revokeObjectURL })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const wrapper = mount(RecoveryCodesDisplay, { props: { codes: CODES } })

    await wrapper.find('[data-testid="download-recovery-codes"]').trigger('click')

    const blob = createObjectURL.mock.calls[0]![0]
    expect(await blob.text()).toContain('abcde-12345\nfghij-67890')
    expect(click).toHaveBeenCalled()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:codes')
  })

  it('warns and allows continuing when no codes were returned', async () => {
    const wrapper = mount(RecoveryCodesDisplay, { props: { codes: [] } })

    expect(wrapper.find('[role="alert"]').text()).toContain('could not be generated')
    expect(wrapper.find('input#recovery-codes-saved').exists()).toBe(false)
    await wrapper.find('[data-testid="recovery-codes-done"]').trigger('click')
    expect(wrapper.emitted('done')).toHaveLength(1)
  })
})
