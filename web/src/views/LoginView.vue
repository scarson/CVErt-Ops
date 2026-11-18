<!-- ABOUTME: Login page with email/password form, OAuth provider buttons, and the follow-up sign-in steps. -->
<!-- ABOUTME: Renders the step the server still requires (MFA, forced password change, MFA enrollment), then redirects. -->

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useRoute, useRouter, RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import client from '@/lib/api/client'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Github } from 'lucide-vue-next'
import MfaChallengeStep from '@/components/auth/MfaChallengeStep.vue'
import ForcedPasswordStep from '@/components/auth/ForcedPasswordStep.vue'
import MfaEnrollStep from '@/components/auth/MfaEnrollStep.vue'

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

const SUPPORTED_STEPS = ['mfa_challenge', 'password_reset', 'mfa_enrollment_required']
const currentStep = computed(() => auth.pendingSteps[0] ?? null)
const unsupportedStep = computed(
  () => currentStep.value !== null && !SUPPORTED_STEPS.includes(currentStep.value),
)

function goToRedirect() {
  const redirect = (route.query.redirect as string) || '/cves'
  router.push(redirect)
}

onMounted(async () => {
  const { data } = await client.GET('/auth/providers')
  if (data) {
    githubEnabled.value = data.github === true
    googleEnabled.value = data.google === true
    hasOAuth.value = githubEnabled.value || googleEnabled.value
  }
})

async function onSubmit() {
  error.value = ''
  submitting.value = true

  try {
    const result = await auth.login(email.value, password.value)

    if (result.success) {
      goToRedirect()
    } else if (auth.pendingSteps.length > 0) {
      // The password has done its job; do not keep it around during the steps.
      password.value = ''
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
    <CardContent v-if="currentStep">
      <div v-if="unsupportedStep" class="space-y-4">
        <p class="text-sm text-destructive" role="alert">
          This account needs a sign-in step that cannot be completed in this app. Contact your administrator.
        </p>
        <Button variant="outline" class="w-full" @click="auth.cancelSignIn()">Back to log in</Button>
      </div>
      <MfaChallengeStep v-else-if="currentStep === 'mfa_challenge'" @complete="goToRedirect" />
      <ForcedPasswordStep v-else-if="currentStep === 'password_reset'" @complete="goToRedirect" />
      <MfaEnrollStep v-else @complete="goToRedirect" />
    </CardContent>
    <CardHeader v-if="!currentStep" class="text-center">
      <CardTitle class="text-xl">Log in to your account</CardTitle>
    </CardHeader>
    <CardContent v-if="!currentStep">
      <p v-if="auth.signInNotice" class="mb-4 text-sm text-muted-foreground" role="status" data-testid="sign-in-notice">
        {{ auth.signInNotice }}
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
