<!-- ABOUTME: Forgot password page — email form to request a password reset link. -->
<!-- ABOUTME: Always shows success message regardless of whether the email exists (anti-enumeration). -->

<script setup lang="ts">
import { ref } from 'vue'
import { RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const auth = useAuthStore()

const email = ref('')
const submitting = ref(false)
const submitted = ref(false)
const error = ref('')

async function onSubmit() {
  error.value = ''
  submitting.value = true

  try {
    const result = await auth.forgotPassword(email.value)
    if (result.success) {
      submitted.value = true
    } else {
      // Still show success message to prevent email enumeration.
      submitted.value = true
    }
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <Card>
    <CardHeader class="text-center">
      <CardTitle class="text-xl">Forgot your password?</CardTitle>
    </CardHeader>
    <CardContent>
      <template v-if="!submitted">
        <p class="mb-4 text-sm text-muted-foreground">
          Enter your email address and we'll send you a link to reset your password.
        </p>
        <form class="space-y-4" @submit.prevent="onSubmit">
          <div class="space-y-2">
            <Label for="email">Email</Label>
            <Input
              id="email"
              v-model="email"
              type="email"
              placeholder="you@example.com"
              required
              autocomplete="email"
            />
          </div>

          <p v-if="error" class="text-sm text-destructive" role="alert">{{ error }}</p>

          <Button type="submit" class="w-full" :disabled="submitting">
            {{ submitting ? 'Sending...' : 'Send reset link' }}
          </Button>
        </form>
      </template>

      <template v-else>
        <p class="text-sm text-muted-foreground">
          If an account with that email exists, a password reset link has been sent.
          Check your inbox (and spam folder).
        </p>
      </template>

      <p class="mt-6 text-center text-sm text-muted-foreground">
        <RouterLink to="/login" class="font-medium text-foreground underline underline-offset-4 hover:text-primary">
          Back to login
        </RouterLink>
      </p>
    </CardContent>
  </Card>
</template>
