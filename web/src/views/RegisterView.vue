<!-- ABOUTME: Registration page with email/password form and OAuth provider buttons. -->
<!-- ABOUTME: Handles invite-only mode errors and auto-logs in after successful registration. -->

<script setup lang="ts">
import { ref } from 'vue'
import { RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import client from '@/lib/api/client'
import type { components } from '@/lib/api/schema'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Github } from 'lucide-vue-next'

const auth = useAuthStore()

const email = ref('')
const password = ref('')
const confirmPassword = ref('')
const displayName = ref('')
const error = ref('')
const submitting = ref(false)

async function onSubmit() {
  error.value = ''

  if (password.value !== confirmPassword.value) {
    error.value = 'Passwords do not match'
    return
  }

  submitting.value = true

  try {
    const body: components['schemas']['RegisterInputBody'] = {
      email: email.value,
      password: password.value,
    }
    if (displayName.value.trim()) {
      body.display_name = displayName.value.trim()
    }

    const { error: apiError, response } = await client.POST('/auth/register', { body })

    if (apiError) {
      if (response?.status === 409) {
        error.value = 'Email already registered'
      } else if (response?.status === 403) {
        error.value = 'Registration is invite-only'
      } else {
        error.value = 'Registration failed'
      }
      return
    }

    // Auto-login after successful registration.
    await auth.login(email.value, password.value)
  } finally {
    submitting.value = false
  }
}

function registerWithGitHub() {
  window.location.href = '/api/v1/auth/oauth/github'
}

function registerWithGoogle() {
  window.location.href = '/api/v1/auth/oauth/google'
}
</script>

<template>
  <Card>
    <CardHeader class="text-center">
      <CardTitle class="text-xl">Create your account</CardTitle>
    </CardHeader>
    <CardContent>
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
        <div class="space-y-2">
          <Label for="display-name">Display name</Label>
          <Input
            id="display-name"
            v-model="displayName"
            type="text"
            placeholder="Optional"
            autocomplete="name"
          />
        </div>
        <div class="space-y-2">
          <Label for="password">Password</Label>
          <Input
            id="password"
            v-model="password"
            type="password"
            placeholder="Enter your password"
            required
            autocomplete="new-password"
          />
          <p class="text-xs text-muted-foreground">16+ characters</p>
        </div>
        <div class="space-y-2">
          <Label for="confirm-password">Confirm password</Label>
          <Input
            id="confirm-password"
            v-model="confirmPassword"
            type="password"
            placeholder="Confirm your password"
            required
            autocomplete="new-password"
          />
        </div>

        <p v-if="error" class="text-sm text-destructive">{{ error }}</p>

        <Button type="submit" class="w-full" :disabled="submitting">
          {{ submitting ? 'Registering...' : 'Register' }}
        </Button>
      </form>

      <div class="relative my-6 flex items-center">
        <Separator class="flex-1" />
        <span class="px-3 text-xs text-muted-foreground">or continue with</span>
        <Separator class="flex-1" />
      </div>

      <div class="grid grid-cols-2 gap-3">
        <Button variant="outline" type="button" @click="registerWithGitHub">
          <Github class="mr-2 size-4" />
          GitHub
        </Button>
        <Button variant="outline" type="button" @click="registerWithGoogle">
          Google
        </Button>
      </div>

      <p class="mt-6 text-center text-sm text-muted-foreground">
        Already have an account?
        <RouterLink to="/login" class="font-medium text-foreground underline underline-offset-4 hover:text-primary">
          Log in
        </RouterLink>
      </p>
    </CardContent>
  </Card>
</template>
