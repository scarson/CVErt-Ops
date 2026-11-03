<!-- ABOUTME: Enrolls an MFA method (authenticator app via QR code, or email codes), used at sign-in and in account settings. -->
<!-- ABOUTME: Emits 'enrolled' with any recovery codes, or 'session-expired' when the sign-in session is rejected. -->

<script setup lang="ts">
import { computed, ref } from 'vue'
import { renderSVG } from 'uqr'
import client from '@/lib/api/client'
import {
  PROBLEM_ENROLLMENT_EXPIRED,
  PROBLEM_INVALID_CODE,
  PROBLEM_PENDING_SESSION_INVALID,
  problemDetail,
  problemType,
} from '@/lib/api/problems'
import type { MfaMethod } from '@/stores/auth'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const props = defineProps<{ enrolledMethods: string[] }>()
const emit = defineEmits<{
  enrolled: [recoveryCodes: string[]]
  'session-expired': []
}>()

const METHOD_LABELS: Record<MfaMethod, string> = {
  totp: 'Authenticator app',
  email_otp: 'Email codes',
}

const availableMethods = computed(() =>
  (['totp', 'email_otp'] as const).filter((m) => !props.enrolledMethods.includes(m)),
)

const method = ref<MfaMethod | null>(null)
const qrDataUrl = ref('')
const secret = ref('')
const showSecret = ref(false)
const code = ref('')
const error = ref('')
const busy = ref(false)

// Reports a failed call: a rejected sign-in session goes to the parent,
// anything else is shown inline.
function fail(err: unknown, fallback: string) {
  const type = problemType(err)
  if (type === PROBLEM_PENDING_SESSION_INVALID) {
    emit('session-expired')
    return
  }
  error.value = type === PROBLEM_INVALID_CODE ? 'That code is not correct. Try again.' : problemDetail(err, fallback)
}

async function setupTotp() {
  const { data, error: err } = await client.POST('/auth/mfa/totp/setup')
  if (err || !data) {
    fail(err, 'Could not start authenticator setup')
    return false
  }
  qrDataUrl.value = `data:image/svg+xml,${encodeURIComponent(renderSVG(data.qr_code_uri))}`
  secret.value = data.secret
  showSecret.value = false
  return true
}

async function choose(next: MfaMethod) {
  busy.value = true
  error.value = ''
  code.value = ''
  let started: boolean
  if (next === 'totp') {
    started = await setupTotp()
  } else {
    const { error: err } = await client.POST('/auth/mfa/email-otp/setup')
    started = !err
    if (err) fail(err, 'Could not send a verification code')
  }
  busy.value = false
  if (started) method.value = next
}

async function confirm() {
  const value = code.value.trim()
  if (!value || busy.value || !method.value) return
  busy.value = true
  error.value = ''
  const path = method.value === 'totp' ? '/auth/mfa/totp/confirm' : '/auth/mfa/email-otp/confirm'
  const { data, error: err } = await client.POST(path, { body: { code: value } })
  if (err) {
    if (problemType(err) === PROBLEM_ENROLLMENT_EXPIRED) {
      code.value = ''
      if (await setupTotp()) {
        error.value = 'Setup timed out and the previous QR code no longer works. Scan this new code.'
      }
    } else {
      fail(err, 'Could not confirm the code')
    }
    busy.value = false
    return
  }
  busy.value = false
  emit('enrolled', data?.recovery_codes ?? [])
}

async function copySecret() {
  await navigator.clipboard.writeText(secret.value)
}
</script>

<template>
  <div class="space-y-4">
    <div v-if="!method" class="grid gap-2" role="group" aria-label="Two-factor method">
      <Button
        v-for="m in availableMethods"
        :key="m"
        type="button"
        variant="outline"
        class="justify-start"
        :disabled="busy"
        :data-testid="`enroll-${m}`"
        @click="choose(m)"
      >
        {{ METHOD_LABELS[m] }}{{ m === 'totp' ? ' (recommended)' : '' }}
      </Button>
    </div>

    <template v-else>
      <div v-if="method === 'totp'" class="space-y-3">
        <p class="text-sm text-muted-foreground">Scan this QR code with your authenticator app.</p>
        <img
          :src="qrDataUrl"
          alt="QR code for your authenticator app"
          data-testid="totp-qr"
          class="mx-auto size-48 rounded-md bg-white p-2"
        />
        <div class="text-sm">
          <button
            type="button"
            class="text-muted-foreground underline underline-offset-4 hover:text-primary"
            data-testid="show-totp-secret"
            :aria-expanded="showSecret"
            @click="showSecret = !showSecret"
          >
            Can't scan? Show secret key
          </button>
          <div v-if="showSecret" class="mt-2 flex items-center gap-2">
            <code class="break-all rounded bg-muted px-2 py-1 font-mono text-xs">{{ secret }}</code>
            <Button type="button" size="sm" variant="outline" @click="copySecret">Copy</Button>
          </div>
        </div>
      </div>
      <p v-else class="text-sm text-muted-foreground">
        We sent a 6-digit code to your email address.
      </p>

      <form class="space-y-3" @submit.prevent="confirm">
        <div class="space-y-2">
          <Label for="enroll-code">Verification code</Label>
          <Input
            id="enroll-code"
            v-model="code"
            inputmode="numeric"
            autocomplete="one-time-code"
            placeholder="123456"
            required
            :aria-invalid="!!error || undefined"
            :aria-describedby="error ? 'enroll-error' : undefined"
          />
        </div>
        <Button type="submit" class="w-full" :disabled="busy">
          {{ busy ? 'Checking...' : 'Confirm' }}
        </Button>
      </form>
    </template>

    <div aria-live="polite">
      <p v-if="error" id="enroll-error" class="text-sm text-destructive" role="alert">{{ error }}</p>
    </div>
  </div>
</template>
