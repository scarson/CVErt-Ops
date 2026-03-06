<!-- ABOUTME: Invitation acceptance page for org invitations. -->
<!-- ABOUTME: Fetches invitation details by token, handles login redirect and accept flow. -->

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter, RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import client from '@/lib/api/client'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const token = route.params.token as string

const loading = ref(true)
const invitation = ref<{ org_name: string; role: string; expires_at: string } | null>(null)
const error = ref('')
const acceptError = ref('')
const accepting = ref(false)

onMounted(async () => {
  const { data, error: apiError, response } = await client.GET('/auth/invitations/{token}', {
    params: { path: { token } },
  })

  loading.value = false

  if (apiError) {
    const status = (response as Response | undefined)?.status
    if (status === 404) {
      error.value = 'This invitation link is invalid.'
    } else if (status === 410) {
      error.value = 'This invitation has expired or has already been used.'
    } else {
      error.value = 'Failed to load invitation details.'
    }
    return
  }

  invitation.value = data
})

async function acceptInvitation() {
  acceptError.value = ''
  accepting.value = true

  try {
    const { error: apiError, response } = await client.POST('/auth/invitations/{token}/accept', {
      params: { path: { token } },
    })

    if (apiError) {
      const status = (response as Response | undefined)?.status
      if (status === 401) {
        acceptError.value = 'Please log in first'
      } else if (status === 403) {
        acceptError.value = 'This invitation was sent to a different email'
      } else if (status === 410) {
        acceptError.value = 'Invitation expired'
      } else {
        acceptError.value = 'Failed to accept invitation'
      }
      return
    }

    await auth.fetchMe()
    // Activate the org the user just joined.
    const joinedOrg = auth.user?.orgs?.find((o) => o.name === invitation.value?.org_name)
    if (joinedOrg) {
      auth.setActiveOrg(joinedOrg.org_id)
    }
    router.push('/cves')
  } finally {
    accepting.value = false
  }
}
</script>

<template>
  <Card class="mx-auto max-w-md">
    <CardHeader class="text-center">
      <CardTitle class="text-xl">Accept Invitation</CardTitle>
    </CardHeader>
    <CardContent>
      <!-- Loading state -->
      <div v-if="loading" data-testid="loading">
        <p class="text-center text-muted-foreground">Loading invitation...</p>
      </div>

      <!-- Error state -->
      <div v-else-if="error" data-testid="error">
        <p class="text-center text-sm text-destructive">{{ error }}</p>
      </div>

      <!-- Invitation loaded -->
      <div v-else-if="invitation" class="space-y-4" data-testid="invitation-info">
        <div class="text-center space-y-1">
          <p class="text-sm text-muted-foreground">You've been invited to join</p>
          <p class="text-lg font-semibold">{{ invitation.org_name }}</p>
          <p class="text-sm text-muted-foreground">
            as <span class="font-medium">{{ invitation.role }}</span>
          </p>
        </div>

        <!-- Accept error -->
        <p v-if="acceptError" class="text-sm text-destructive text-center">{{ acceptError }}</p>

        <!-- Unauthenticated: show login link -->
        <template v-if="!auth.isAuthenticated">
          <Button as-child class="w-full">
            <RouterLink
              :to="`/login?redirect=/invitations/${token}`"
              data-testid="login-link"
            >
              Log in to accept
            </RouterLink>
          </Button>
        </template>

        <!-- Authenticated: show accept button -->
        <template v-else>
          <Button
            class="w-full"
            data-testid="accept-button"
            :disabled="accepting"
            @click="acceptInvitation"
          >
            {{ accepting ? 'Accepting...' : 'Accept Invitation' }}
          </Button>
        </template>
      </div>
    </CardContent>
  </Card>
</template>
