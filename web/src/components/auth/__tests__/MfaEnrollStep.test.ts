// ABOUTME: Tests for the mandatory MFA enrollment step shown during sign-in.
// ABOUTME: Covers recovery code hand-off, completing sign-in, session expiry, and cancel.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { defineComponent, h } from 'vue'
import { useAuthStore } from '@/stores/auth'
import MfaEnrollStep from '../MfaEnrollStep.vue'

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn<(...args: unknown[]) => unknown>(),
    POST: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

// Stand-in for MfaEnrollment so the step's hand-off logic is tested in isolation.
const MfaEnrollmentStub = defineComponent({
  name: 'MfaEnrollment',
  props: { enrolledMethods: { type: Array, required: true } },
  emits: ['enrolled', 'session-expired'],
  setup() {
    return () => h('div', { 'data-testid': 'mfa-enrollment' })
  },
})

async function mountStep() {
  const auth = useAuthStore()
  auth.pendingSteps = ['mfa_enrollment_required']
  const finishSpy = vi.spyOn(auth, 'finishSignIn').mockResolvedValue({ ok: true, complete: true })
  const expireSpy = vi.spyOn(auth, 'expireSignIn')
  const cancelSpy = vi.spyOn(auth, 'cancelSignIn').mockResolvedValue()
  const wrapper = mount(MfaEnrollStep, {
    attachTo: document.body,
    global: { stubs: { MfaEnrollment: MfaEnrollmentStub } },
  })
  await flushPromises()
  return { wrapper, finishSpy, expireSpy, cancelSpy }
}

describe('MfaEnrollStep', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    document.body.innerHTML = ''
  })

  it('explains that MFA is required and offers enrollment', async () => {
    const { wrapper } = await mountStep()

    expect(wrapper.text()).toContain('requires two-factor authentication')
    expect(wrapper.findComponent(MfaEnrollmentStub).props('enrolledMethods')).toEqual([])
    expect(document.activeElement?.tagName).toBe('H2')
  })

  it('shows the recovery codes, then completes sign-in', async () => {
    const { wrapper, finishSpy } = await mountStep()

    wrapper.findComponent(MfaEnrollmentStub).vm.$emit('enrolled', ['abcde-12345'])
    await flushPromises()
    expect(wrapper.text()).toContain('abcde-12345')
    expect(finishSpy).not.toHaveBeenCalled()

    await wrapper.find('input#recovery-codes-saved').setValue(true)
    await wrapper.find('[data-testid="recovery-codes-done"]').trigger('click')
    await flushPromises()

    expect(finishSpy).toHaveBeenCalled()
    expect(wrapper.emitted('complete')).toHaveLength(1)
  })

  it('returns to the password form when the sign-in session expired', async () => {
    const { wrapper, expireSpy } = await mountStep()

    wrapper.findComponent(MfaEnrollmentStub).vm.$emit('session-expired')

    expect(expireSpy).toHaveBeenCalled()
  })

  it('cancels the sign-in', async () => {
    const { wrapper, cancelSpy } = await mountStep()

    await wrapper.find('[data-testid="cancel-sign-in"]').trigger('click')

    expect(cancelSpy).toHaveBeenCalled()
  })
})
