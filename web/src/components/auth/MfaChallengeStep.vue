<!-- ABOUTME: Sign-in step that asks for a second factor: authenticator code, email code, or recovery code. -->
<!-- ABOUTME: Emits 'complete' when the server reports no remaining sign-in steps. -->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useAuthStore, type MfaMethod, type MfaVerifyMethod } from '@/stores/auth'
import { PROBLEM_INVALID_CODE } from '@/lib/api/problems'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const emit = defineEmits<{ complete: [] }>()

// The server deletes an email challenge after this many wrong codes.
const EMAIL_CODE_MAX_ATTEMPTS = 3

const auth = useAuthStore()

const enrolledMethods = computed(() =>
  auth.mfaMethods.filter((m): m is MfaMethod => m === 'totp' || m === 'email_otp'),
)
const method = ref<MfaMethod>(enrolledMethods.value.includes('totp') ? 'totp' : 'email_otp')
const useRecovery = ref(false)
const code = ref('')
const rememberDevice = ref(false)
const error = ref('')
const submitting = ref(false)
const emailSent = ref(false)
const sending = ref(false)
const emailFailures = ref(0)
const heading = ref<HTMLHeadingElement | null>(null)

const activeMethod = computed<MfaVerifyMethod>(() => (useRecovery.value ? 'recovery' : method.value))
// The server only issues a remember-device token when this is the final step.
const offerRememberDevice = computed(
  () => auth.pendingSteps.length === 1 && auth.pendingSteps[0] === 'mfa_challenge',
)
const showCodeForm = computed(() => useRecovery.value || method.value === 'totp' || emailSent.value)

onMounted(async () => {
  heading.value?.focus()
  if (method.value === 'totp') {
    await auth.startMfaChallenge('totp')
  }
})

async function chooseMethod(next: MfaMethod) {
  method.value = next
  useRecovery.value = false
  code.value = ''
  error.value = ''
  if (next === 'totp') {
    await auth.startMfaChallenge('totp')
  }
}

async function sendEmailCode() {
  sending.value = true
  error.value = ''
  const result = await auth.startMfaChallenge('email_otp')
  sending.value = false
  if (!result.ok) {
    error.value = result.error ?? 'Could not send a code'
    return
  }
  emailSent.value = true
  emailFailures.value = 0
  code.value = ''
}

function toggleRecovery() {
  useRecovery.value = !useRecovery.value
  code.value = ''
  error.value = ''
}

async function onSubmit() {
  const value = code.value.trim()
  if (!value || submitting.value) return
  submitting.value = true
  error.value = ''
  const result = await auth.verifyMfa(activeMethod.value, value, offerRememberDevice.value && rememberDevice.value)
  submitting.value = false
  if (result.ok) {
    if (result.complete) emit('complete')
    return
  }
  if (activeMethod.value === 'email_otp' && result.problemType === PROBLEM_INVALID_CODE) {
    emailFailures.value++
    if (emailFailures.value >= EMAIL_CODE_MAX_ATTEMPTS) {
      error.value = 'Too many incorrect codes. Request a new code.'
      return
    }
  }
  error.value = result.error ?? 'Verification failed'
}
</script>

<template>
  <div class="space-y-4">
    <div class="space-y-1 text-center">
      <h2 ref="heading" tabindex="-1" class="text-xl font-semibold outline-none">Two-factor authentication</h2>
      <p class="text-sm text-muted-foreground">
        <template v-if="useRecovery">Enter one of your recovery codes.</template>
        <template v-else-if="method === 'totp'">Enter the 6-digit code from your authenticator app.</template>
        <template v-else>We can email a 6-digit code to {{ auth.signInEmail || 'your address' }}.</template>
      </p>
    </div>

    <div v-if="enrolledMethods.length > 1 && !useRecovery" class="grid grid-cols-2 gap-2" role="group" aria-label="Verification method">
      <Button
        v-for="m in enrolledMethods"
        :key="m"
        type="button"
        :variant="method === m ? 'default' : 'outline'"
        :aria-pressed="method === m"
        :data-testid="`method-${m}`"
        @click="chooseMethod(m)"
      >
        {{ m === 'totp' ? 'Authenticator app' : 'Email code' }}
      </Button>
    </div>

    <div v-if="method === 'email_otp' && !useRecovery" class="space-y-2">
      <p v-if="emailSent" class="text-sm text-muted-foreground">
        Check your email for the code. Only the most recent code works.
      </p>
      <Button
        type="button"
        variant="outline"
        class="w-full"
        data-testid="send-email-code"
        :disabled="sending"
        @click="sendEmailCode"
      >
        {{ sending ? 'Sending...' : emailSent ? 'Resend code' : 'Email me a code' }}
      </Button>
    </div>

    <form v-if="showCodeForm" class="space-y-4" @submit.prevent="onSubmit">
      <div class="space-y-2">
        <Label for="mfa-code">{{ useRecovery ? 'Recovery code' : 'Verification code' }}</Label>
        <Input
          id="mfa-code"
          v-model="code"
          :inputmode="useRecovery ? 'text' : 'numeric'"
          :autocomplete="useRecovery ? 'off' : 'one-time-code'"
          :placeholder="useRecovery ? 'xxxxx-xxxxx' : '123456'"
          required
          :aria-invalid="!!error || undefined"
          :aria-describedby="error ? 'mfa-error' : undefined"
        />
      </div>

      <label v-if="offerRememberDevice" class="flex items-start gap-2 text-sm">
        <input id="remember-device" v-model="rememberDevice" type="checkbox" class="mt-0.5 size-4 accent-primary" />
        <span>Remember this device if your organization allows it</span>
      </label>

      <Button type="submit" class="w-full" :disabled="submitting">
        {{ submitting ? 'Verifying...' : 'Verify' }}
      </Button>
    </form>

    <div aria-live="polite">
      <p v-if="error" id="mfa-error" class="text-sm text-destructive" role="alert">{{ error }}</p>
    </div>

    <div class="flex items-center justify-between text-sm">
      <button
        type="button"
        class="text-muted-foreground underline underline-offset-4 hover:text-primary"
        data-testid="use-recovery-code"
        @click="toggleRecovery"
      >
        {{ useRecovery ? 'Use a verification code instead' : 'Use a recovery code' }}
      </button>
      <button
        type="button"
        class="text-muted-foreground underline underline-offset-4 hover:text-primary"
        data-testid="cancel-sign-in"
        @click="auth.cancelSignIn()"
      >
        Cancel
      </button>
    </div>
  </div>
</template>
