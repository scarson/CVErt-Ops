<!-- ABOUTME: Sign-in step for users whose organization requires MFA but who have no method enrolled. -->
<!-- ABOUTME: Shows the recovery codes after enrollment, then emits 'complete' once sign-in finishes. -->

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import MfaEnrollment from '@/components/mfa/MfaEnrollment.vue'
import RecoveryCodesDisplay from '@/components/mfa/RecoveryCodesDisplay.vue'

const emit = defineEmits<{ complete: [] }>()

const auth = useAuthStore()
const recoveryCodes = ref<string[] | null>(null)
const error = ref('')
const heading = ref<HTMLHeadingElement | null>(null)

onMounted(() => heading.value?.focus())

// Enrollment is always the last sign-in step, so a successful confirm has
// already issued the full session cookies.
function onEnrolled(codes: string[]) {
  recoveryCodes.value = codes
}

async function onCodesSaved() {
  const result = await auth.finishSignIn()
  if (!result.ok) {
    error.value = result.error ?? 'Sign-in could not be completed'
    return
  }
  emit('complete')
}
</script>

<template>
  <div class="space-y-4">
    <div class="space-y-1 text-center">
      <h2 ref="heading" tabindex="-1" class="text-xl font-semibold outline-none">
        {{ recoveryCodes ? 'Save your recovery codes' : 'Set up two-factor authentication' }}
      </h2>
      <p v-if="!recoveryCodes" class="text-sm text-muted-foreground">
        Your organization requires two-factor authentication. Choose a method to continue.
      </p>
    </div>

    <RecoveryCodesDisplay v-if="recoveryCodes" :codes="recoveryCodes" @done="onCodesSaved" />
    <MfaEnrollment
      v-else
      :enrolled-methods="[]"
      @enrolled="onEnrolled"
      @session-expired="auth.expireSignIn()"
    />

    <div aria-live="polite">
      <p v-if="error" class="text-sm text-destructive" role="alert">{{ error }}</p>
    </div>

    <div v-if="!recoveryCodes" class="text-right text-sm">
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
