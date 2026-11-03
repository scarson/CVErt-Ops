// ABOUTME: Tests for the forced password change step shown during sign-in.
// ABOUTME: Covers validation, password-manager hints, submission, completion, and errors.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'

vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn<(...args: unknown[]) => unknown>(),
    POST: vi.fn<(...args: unknown[]) => unknown>(),
  },
}))

async function mountStep() {
  const auth = useAuthStore()
  auth.pendingSteps = ['password_reset']
  auth.signInEmail = 'reset@example.com'
  const changeSpy = vi
    .spyOn(auth, 'completeForcedPasswordChange')
    .mockResolvedValue({ ok: true, complete: true })
  const cancelSpy = vi.spyOn(auth, 'cancelSignIn').mockResolvedValue()
  const { default: ForcedPasswordStep } = await import('../ForcedPasswordStep.vue')
  const wrapper = mount(ForcedPasswordStep, { attachTo: document.body })
  await flushPromises()
  return { wrapper, changeSpy, cancelSpy }
}

async function fill(wrapper: Awaited<ReturnType<typeof mountStep>>['wrapper'], pw: string, confirm: string) {
  await wrapper.find('input#new-password').setValue(pw)
  await wrapper.find('input#confirm-password').setValue(confirm)
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

describe('ForcedPasswordStep', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    document.body.innerHTML = ''
  })

  it('gives password managers the account name and a new-password field', async () => {
    const { wrapper } = await mountStep()

    const username = wrapper.find('input[autocomplete="username"]')
    expect((username.element as HTMLInputElement).value).toBe('reset@example.com')
    expect(wrapper.find('input#new-password').attributes('autocomplete')).toBe('new-password')
    expect(wrapper.find('input#current-password').exists()).toBe(false)
  })

  it('rejects passwords shorter than 16 characters', async () => {
    const { wrapper, changeSpy } = await mountStep()

    await fill(wrapper, 'short-pass', 'short-pass')

    expect(changeSpy).not.toHaveBeenCalled()
    expect(wrapper.find('[role="alert"]').text()).toContain('at least 16 characters')
  })

  it('rejects mismatched confirmation', async () => {
    const { wrapper, changeSpy } = await mountStep()

    await fill(wrapper, 'a-long-new-password-1', 'a-long-new-password-2')

    expect(changeSpy).not.toHaveBeenCalled()
    expect(wrapper.find('[role="alert"]').text()).toContain('do not match')
  })

  it('submits the new password and emits complete', async () => {
    const { wrapper, changeSpy } = await mountStep()

    await fill(wrapper, 'a-long-new-password-1', 'a-long-new-password-1')

    expect(changeSpy).toHaveBeenCalledWith('a-long-new-password-1')
    expect(wrapper.emitted('complete')).toHaveLength(1)
  })

  it('shows the server error', async () => {
    const { wrapper, changeSpy } = await mountStep()
    changeSpy.mockResolvedValueOnce({ ok: false, error: 'server busy, please retry' })

    await fill(wrapper, 'a-long-new-password-1', 'a-long-new-password-1')

    expect(wrapper.find('[role="alert"]').text()).toBe('server busy, please retry')
    expect(wrapper.emitted('complete')).toBeUndefined()
  })

  it('cancels the sign-in', async () => {
    const { wrapper, cancelSpy } = await mountStep()

    await wrapper.find('[data-testid="cancel-sign-in"]').trigger('click')

    expect(cancelSpy).toHaveBeenCalled()
  })
})
