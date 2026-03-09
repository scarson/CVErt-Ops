<!-- ABOUTME: Login page with email/password form and OAuth provider buttons. -->
<!-- ABOUTME: Handles redirect query param and displays auth errors from the store. -->

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter, RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Github } from 'lucide-vue-next'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const email = ref('')
const password = ref('')
const error = ref('')
const submitting = ref(false)
const githubEnabled = ref(false)
const googleEnabled = ref(false)
const hasOAuth = ref(false)

onMounted(async () => {
  try {
    const resp = await fetch('/api/v1/auth/providers')
    if (resp.ok) {
      const data = await resp.json()
      githubEnabled.value = data.github === true
      googleEnabled.value = data.google === true
      hasOAuth.value = githubEnabled.value || googleEnabled.value
    }
  } catch {
    // Providers endpoint unavailable — hide OAuth buttons
  }
})

async function onSubmit() {
  error.value = ''
  submitting.value = true

  try {
    const result = await auth.login(email.value, password.value)

    if (result.success) {
      const redirect = (route.query.redirect as string) || '/cves'
      router.push(redirect)
    } else {
      error.value = result.error ?? 'Login failed'
    }
  } finally {
    submitting.value = false
  }
}

function loginWithGitHub() {
  window.location.href = '/api/v1/auth/oauth/github'
}

function loginWithGoogle() {
  window.location.href = '/api/v1/auth/oauth/google'
}
</script>

<template>
  <Card>
    <CardHeader class="text-center">
      <CardTitle class="text-xl">Log in to your account</CardTitle>
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
            :aria-invalid="!!error || undefined"
            :aria-describedby="error ? 'login-error' : undefined"
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
            autocomplete="current-password"
            :aria-invalid="!!error || undefined"
            :aria-describedby="error ? 'login-error' : undefined"
          />
          <div class="text-right">
            <RouterLink to="/forgot-password" class="text-xs text-muted-foreground underline underline-offset-4 hover:text-primary">
              Forgot password?
            </RouterLink>
          </div>
        </div>

        <p v-if="error" id="login-error" class="text-sm text-destructive" role="alert">{{ error }}</p>

        <Button type="submit" class="w-full" :disabled="submitting">
          {{ submitting ? 'Logging in...' : 'Log in' }}
        </Button>
      </form>

      <template v-if="hasOAuth">
        <div class="relative my-6 flex items-center">
          <Separator class="flex-1" />
          <span class="px-3 text-xs text-muted-foreground">or continue with</span>
          <Separator class="flex-1" />
        </div>

        <div class="flex gap-3" :class="githubEnabled && googleEnabled ? 'grid grid-cols-2' : ''">
          <Button v-if="githubEnabled" variant="outline" type="button" class="flex-1" @click="loginWithGitHub">
            <Github class="mr-2 size-4" aria-hidden="true" />
            GitHub
          </Button>
          <Button v-if="googleEnabled" variant="outline" type="button" class="flex-1" @click="loginWithGoogle">
            Google
          </Button>
        </div>
      </template>

      <p class="mt-6 text-center text-sm text-muted-foreground">
        Don't have an account?
        <RouterLink to="/register" class="font-medium text-foreground underline underline-offset-4 hover:text-primary">
          Register
        </RouterLink>
      </p>
    </CardContent>
  </Card>
</template>
