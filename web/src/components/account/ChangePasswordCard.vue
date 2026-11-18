<!-- ABOUTME: Account page card for changing the signed-in user's password. -->
<!-- ABOUTME: Signs the user out afterwards, because the server ends existing sessions on a password change. -->

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import client from '@/lib/api/client'
import { PROBLEM_INVALID_PASSWORD, problemDetail, problemType } from '@/lib/api/problems'
import { MIN_PASSWORD_LENGTH, validateNewPassword } from '@/lib/password'
import { useAuthStore } from '@/stores/auth'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const auth = useAuthStore()
const router = useRouter()

const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const error = ref('')
const submitting = ref(false)

async function onSubmit() {
  error.value = validateNewPassword(newPassword.value, confirmPassword.value)
  if (error.value || submitting.value) return
  submitting.value = true
  const { error: err } = await client.POST('/auth/change-password', {
    body: { current_password: currentPassword.value, new_password: newPassword.value },
  })
  if (err) {
    submitting.value = false
    error.value =
      problemType(err) === PROBLEM_INVALID_PASSWORD
        ? 'Your current password is not correct.'
        : problemDetail(err, 'Password change failed')
    return
  }
  // The server bumps the session version without issuing new cookies, so the
  // current session would end at the next refresh; end it now instead.
  await auth.logout()
  auth.signInNotice = 'Password changed. Sign in again.'
  submitting.value = false
  router.push({ name: 'login' })
}
</script>

<template>
  <Card>
    <CardHeader>
      <CardTitle>Password</CardTitle>
      <CardDescription v-if="auth.user?.has_password">
        Changing your password signs you out everywhere.
      </CardDescription>
    </CardHeader>
    <CardContent>
      <p v-if="!auth.user?.has_password" class="text-sm text-muted-foreground">
        This account signs in through an external identity provider, so it has no password here.
      </p>
      <form v-else class="max-w-md space-y-4" @submit.prevent="onSubmit">
        <input type="email" autocomplete="username" :value="auth.user?.email" readonly tabindex="-1" aria-hidden="true" class="sr-only" />
        <div class="space-y-2">
          <Label for="current-password">Current password</Label>
          <Input id="current-password" v-model="currentPassword" type="password" autocomplete="current-password" required />
        </div>
        <div class="space-y-2">
          <Label for="account-new-password">New password</Label>
          <Input
            id="account-new-password"
            v-model="newPassword"
            type="password"
            autocomplete="new-password"
            :minlength="MIN_PASSWORD_LENGTH"
            required
            aria-describedby="account-new-password-hint"
          />
          <p id="account-new-password-hint" class="text-xs text-muted-foreground">
            At least {{ MIN_PASSWORD_LENGTH }} characters.
          </p>
        </div>
        <div class="space-y-2">
          <Label for="account-confirm-password">Confirm new password</Label>
          <Input id="account-confirm-password" v-model="confirmPassword" type="password" autocomplete="new-password" required />
        </div>
        <div aria-live="polite">
          <p v-if="error" class="text-sm text-destructive" role="alert">{{ error }}</p>
        </div>
        <Button type="submit" :disabled="submitting">
          {{ submitting ? 'Saving...' : 'Change password' }}
        </Button>
      </form>
    </CardContent>
  </Card>
</template>
