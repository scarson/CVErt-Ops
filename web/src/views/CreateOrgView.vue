<!-- ABOUTME: Create organization page -- shown when an authenticated user has no orgs. -->
<!-- ABOUTME: Posts to the chi-registered /api/v1/orgs endpoint via raw fetch. -->

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const router = useRouter()
const auth = useAuthStore()

const orgName = ref('')
const error = ref('')
const submitting = ref(false)

async function onSubmit() {
  error.value = ''
  submitting.value = true

  try {
    const response = await fetch('/api/v1/orgs', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-By': 'CVErt-Ops',
      },
      body: JSON.stringify({ name: orgName.value }),
    })

    if (!response.ok) {
      error.value = 'Failed to create organization'
      return
    }

    const data: { org_id: string } = await response.json()

    // Refresh user session to pick up the org membership.
    await auth.fetchMe()
    auth.setActiveOrg(data.org_id)
    router.push('/cves')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <Card>
    <CardHeader class="text-center">
      <CardTitle class="text-xl">Create your organization</CardTitle>
    </CardHeader>
    <CardContent>
      <form class="space-y-4" @submit.prevent="onSubmit">
        <div class="space-y-2">
          <Label for="org-name">Organization name</Label>
          <Input
            id="org-name"
            v-model="orgName"
            type="text"
            placeholder="My Organization"
            required
            autocomplete="organization"
          />
        </div>

        <p v-if="error" class="text-sm text-destructive">{{ error }}</p>

        <Button type="submit" class="w-full" :disabled="submitting">
          {{ submitting ? 'Creating...' : 'Create Organization' }}
        </Button>
      </form>
    </CardContent>
  </Card>
</template>
