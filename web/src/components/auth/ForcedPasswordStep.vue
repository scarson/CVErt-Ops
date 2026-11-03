<!-- ABOUTME: Sign-in step that sets a new password when an administrator has forced a reset. -->
<!-- ABOUTME: Emits 'complete' when the server reports no remaining sign-in steps. -->

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { MIN_PASSWORD_LENGTH, validateNewPassword } from '@/lib/password'

const emit = defineEmits<{ complete: [] }>()

const auth = useAuthStore()
const newPassword = ref('')
const confirmPassword = ref('')
const error = ref('')
const submitting = ref(false)
const heading = ref<HTMLHeadingElement | null>(null)

onMounted(() => heading.value?.focus())

async function onSubmit() {
  error.value = validateNewPassword(newPassword.value, confirmPassword.value)
  if (error.value || submitting.value) return
  submitting.value = true
  const result = await auth.completeForcedPasswordChange(newPassword.value)
  submitting.value = false
  if (!result.ok) {
    error.value = result.error ?? 'Password change failed'
    return
  }
  if (result.complete) emit('complete')
}
</script>

<template>
  <div class="space-y-4">
    <div class="space-y-1 text-center">
      <h2 ref="heading" tabindex="-1" class="text-xl font-semibold outline-none">Choose a new password</h2>
      <p class="text-sm text-muted-foreground">
        Your administrator requires a new password before you continue.
      </p>
    </div>

    <form class="space-y-4" @submit.prevent="onSubmit">
      <!-- Lets password managers store the new password under the right account. -->
      <input
        type="email"
        autocomplete="username"
        :value="auth.signInEmail"
        readonly
        tabindex="-1"
        aria-hidden="true"
        class="sr-only"
      />
      <div class="space-y-2">
        <Label for="new-password">New password</Label>
        <Input
          id="new-password"
          v-model="newPassword"
          type="password"
          autocomplete="new-password"
          :minlength="MIN_PASSWORD_LENGTH"
          required
          :aria-invalid="!!error || undefined"
          :aria-describedby="error ? 'forced-password-error' : 'new-password-hint'"
        />
        <p id="new-password-hint" class="text-xs text-muted-foreground">At least {{ MIN_PASSWORD_LENGTH }} characters.</p>
      </div>
      <div class="space-y-2">
        <Label for="confirm-password">Confirm new password</Label>
        <Input
          id="confirm-password"
          v-model="confirmPassword"
          type="password"
          autocomplete="new-password"
          required
          :aria-invalid="!!error || undefined"
        />
      </div>

      <div aria-live="polite">
        <p v-if="error" id="forced-password-error" class="text-sm text-destructive" role="alert">{{ error }}</p>
      </div>

      <Button type="submit" class="w-full" :disabled="submitting">
        {{ submitting ? 'Saving...' : 'Set password and continue' }}
      </Button>
    </form>

    <div class="text-right text-sm">
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
