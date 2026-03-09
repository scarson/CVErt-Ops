<!-- ABOUTME: Email verification page — auto-submits the token from the URL on mount. -->
<!-- ABOUTME: Shows loading, success, or error state based on the verification result. -->

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const route = useRoute()
const auth = useAuthStore()

const token = computed(() => (route.query.token as string) || '')
const loading = ref(true)
const success = ref(false)
const error = ref('')

onMounted(async () => {
  if (!token.value) {
    loading.value = false
    error.value = 'No verification token found in URL.'
    return
  }

  const result = await auth.verifyEmail(token.value)
  loading.value = false

  if (result.success) {
    success.value = true
  } else {
    error.value = result.error ?? 'Verification failed'
  }
})
</script>

<template>
  <Card>
    <CardHeader class="text-center">
      <CardTitle class="text-xl">Email Verification</CardTitle>
    </CardHeader>
    <CardContent class="text-center">
      <p v-if="loading" class="text-sm text-muted-foreground">
        Verifying your email...
      </p>

      <template v-else-if="success">
        <p class="text-sm text-muted-foreground">
          Your email has been verified successfully.
        </p>
        <p class="mt-4">
          <RouterLink to="/login" class="font-medium text-foreground underline underline-offset-4 hover:text-primary">
            Go to login
          </RouterLink>
        </p>
      </template>

      <template v-else>
        <p class="text-sm text-destructive" role="alert">
          {{ error }}
        </p>
        <p class="mt-4 text-sm text-muted-foreground">
          The verification link may have expired. Try logging in and requesting a new verification email.
        </p>
        <p class="mt-4">
          <RouterLink to="/login" class="font-medium text-foreground underline underline-offset-4 hover:text-primary">
            Go to login
          </RouterLink>
        </p>
      </template>
    </CardContent>
  </Card>
</template>
