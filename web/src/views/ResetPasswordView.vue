<!-- ABOUTME: Reset password page — new password form using a token from the URL query string. -->
<!-- ABOUTME: Validates password match and minimum length, redirects to login on success. -->

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute, useRouter, RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const token = computed(() => (route.query.token as string) || '')
const password = ref('')
const confirmPassword = ref('')
const submitting = ref(false)
const success = ref(false)
const error = ref('')

async function onSubmit() {
  error.value = ''

  if (password.value !== confirmPassword.value) {
    error.value = 'Passwords do not match'
    return
  }

  submitting.value = true

  try {
    const result = await auth.resetPassword(token.value, password.value)
    if (result.success) {
      success.value = true
      setTimeout(() => router.push('/login'), 3000)
    } else {
      error.value = result.error ?? 'Reset failed'
    }
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <Card>
    <CardHeader class="text-center">
      <CardTitle class="text-xl">Reset your password</CardTitle>
    </CardHeader>
    <CardContent>
      <template v-if="!token">
        <p class="text-sm text-destructive">
          No reset token found. Please request a new password reset link.
        </p>
        <p class="mt-4 text-center">
          <RouterLink to="/forgot-password" class="font-medium text-foreground underline underline-offset-4 hover:text-primary">
            Forgot password?
          </RouterLink>
        </p>
      </template>

      <template v-else-if="success">
        <p class="text-sm text-muted-foreground">
          Your password has been reset successfully. Redirecting to login...
        </p>
        <p class="mt-4 text-center">
          <RouterLink to="/login" class="font-medium text-foreground underline underline-offset-4 hover:text-primary">
            Go to login
          </RouterLink>
        </p>
      </template>

      <template v-else>
        <form class="space-y-4" @submit.prevent="onSubmit">
          <div class="space-y-2">
            <Label for="password">New password</Label>
            <Input
              id="password"
              v-model="password"
              type="password"
              placeholder="Minimum 16 characters"
              required
              minlength="16"
              autocomplete="new-password"
            />
          </div>
          <div class="space-y-2">
            <Label for="confirm-password">Confirm password</Label>
            <Input
              id="confirm-password"
              v-model="confirmPassword"
              type="password"
              placeholder="Re-enter your password"
              required
              minlength="16"
              autocomplete="new-password"
            />
          </div>

          <p v-if="error" class="text-sm text-destructive" role="alert">{{ error }}</p>

          <Button type="submit" class="w-full" :disabled="submitting">
            {{ submitting ? 'Resetting...' : 'Reset password' }}
          </Button>
        </form>
      </template>

      <p class="mt-6 text-center text-sm text-muted-foreground">
        <RouterLink to="/login" class="font-medium text-foreground underline underline-offset-4 hover:text-primary">
          Back to login
        </RouterLink>
      </p>
    </CardContent>
  </Card>
</template>
