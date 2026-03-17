<!-- ABOUTME: Dialog for creating a watchlist with name and optional description. -->
<!-- ABOUTME: Emits 'created' with the API response on success; shows 409/403 errors inline. -->

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import client from '@/lib/api/client'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

export interface WatchlistEntry {
  id: string
  name: string
  description?: string
  group_id?: string
  item_count: number
  created_at: string
  updated_at: string
}

const props = defineProps<{
  open: boolean
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
  created: [entry: WatchlistEntry]
}>()

const auth = useAuthStore()
const name = ref('')
const description = ref('')
const submitting = ref(false)
const error = ref('')

function resetForm() {
  name.value = ''
  description.value = ''
  error.value = ''
  submitting.value = false
}

watch(
  () => props.open,
  (isOpen) => {
    if (!isOpen) {
      resetForm()
    }
  },
)

async function handleCreate() {
  if (!name.value.trim() || submitting.value) return

  submitting.value = true
  error.value = ''

  const body = {
    name: name.value.trim(),
    description: description.value.trim() || null,
    group_id: null,
  }

  try {
    const { data, error: fetchError } = await client.POST('/orgs/{org_id}/watchlists', {
      params: { path: { org_id: auth.activeOrgId! } },
      body,
    })

    if (fetchError) {
      error.value = fetchError.detail ?? 'Failed to create watchlist'
      submitting.value = false
      return
    }

    emit('created', data as WatchlistEntry)
    emit('update:open', false)
  } catch {
    error.value = 'Network error. Please try again.'
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <Dialog
    :open="props.open"
    data-testid="create-watchlist-dialog"
    @update:open="emit('update:open', $event)"
  >
    <DialogContent :show-close-button="true">
      <DialogHeader>
        <DialogTitle>Create Watchlist</DialogTitle>
        <DialogDescription>
          Create a watchlist to track packages and products for vulnerabilities.
        </DialogDescription>
      </DialogHeader>

      <div class="space-y-4 py-2">
        <div class="space-y-2">
          <Label for="watchlist-name">Name</Label>
          <Input
            id="watchlist-name"
            v-model="name"
            data-testid="watchlist-name-input"
            placeholder="e.g. Production Dependencies"
            :disabled="submitting"
            :aria-invalid="!!error || undefined"
            :aria-describedby="error ? 'create-watchlist-error' : undefined"
          />
        </div>

        <div class="space-y-2">
          <Label for="watchlist-description">Description (optional)</Label>
          <Input
            id="watchlist-description"
            v-model="description"
            data-testid="watchlist-description-input"
            placeholder="What does this watchlist track?"
            :disabled="submitting"
          />
        </div>

        <p v-if="error" id="create-watchlist-error" class="text-sm text-destructive" role="alert" data-testid="create-error">
          {{ error }}
        </p>
      </div>

      <DialogFooter>
        <Button
          variant="outline"
          :disabled="submitting"
          @click="emit('update:open', false)"
        >
          Cancel
        </Button>
        <Button
          data-testid="create-watchlist-btn"
          :disabled="!name.trim() || submitting"
          @click="handleCreate"
        >
          {{ submitting ? 'Creating...' : 'Create' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
