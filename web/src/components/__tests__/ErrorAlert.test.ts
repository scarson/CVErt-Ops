// ABOUTME: Tests for the ErrorAlert component.
// ABOUTME: Covers retry button visibility, click emission, and default title.

import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import ErrorAlert from '../ErrorAlert.vue'

describe('ErrorAlert', () => {
  it('renders retry button when retryable is true', () => {
    const wrapper = mount(ErrorAlert, {
      props: { message: 'Something failed', retryable: true },
    })

    const retryBtn = wrapper.findAll('button').filter((b) => b.text().includes('Retry'))
    expect(retryBtn).toHaveLength(1)
  })

  it('does not render retry button when retryable is not set', () => {
    const wrapper = mount(ErrorAlert, {
      props: { message: 'Something failed' },
    })

    const retryBtn = wrapper.findAll('button').filter((b) => b.text().includes('Retry'))
    expect(retryBtn).toHaveLength(0)
  })

  it('emits retry event when button is clicked', async () => {
    const wrapper = mount(ErrorAlert, {
      props: { message: 'Something failed', retryable: true },
    })

    const retryBtn = wrapper.findAll('button').find((b) => b.text().includes('Retry'))
    await retryBtn!.trigger('click')
    expect(wrapper.emitted('retry')).toHaveLength(1)
  })

  it('renders error message', () => {
    const wrapper = mount(ErrorAlert, {
      props: { message: 'Network error occurred' },
    })

    expect(wrapper.text()).toContain('Network error occurred')
  })

  it('renders custom title when provided', () => {
    const wrapper = mount(ErrorAlert, {
      props: { message: 'Something failed', title: 'Connection Error' },
    })

    expect(wrapper.text()).toContain('Connection Error')
  })

  it('renders default title when not provided', () => {
    const wrapper = mount(ErrorAlert, {
      props: { message: 'Something failed' },
    })

    expect(wrapper.text()).toContain('Error')
  })
})
