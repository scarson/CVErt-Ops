// ABOUTME: Smoke test to verify Vitest + Vue Test Utils setup.
// ABOUTME: Remove this once real component tests exist.

import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { defineComponent } from 'vue'

const TestComponent = defineComponent({
  template: '<div>hello</div>',
})

describe('vitest setup', () => {
  it('mounts a Vue component', () => {
    const wrapper = mount(TestComponent)
    expect(wrapper.text()).toBe('hello')
  })
})
