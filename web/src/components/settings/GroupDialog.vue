<!-- ABOUTME: Dialog for creating or editing an organization group. -->
<!-- ABOUTME: Emits 'saved' with the group entry on success; dual-mode based on group prop. -->

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
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

export interface GroupEntry {
  id: string
  name: string
  description: string
  created_at: string
}

const props = defineProps<{
  open: boolean
  group: GroupEntry | null
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
  saved: [entry: GroupEntry]
}>()

const auth = useAuthStore()
const name = ref('')
const description = ref('')
const submitting = ref(false)
const error = ref('')

const isEdit = computed(() => props.group !== null)

function resetForm() {
  error.value = ''
  submitting.value = false
  if (props.group) {
    name.value = props.group.name
    description.value = props.group.description ?? ''
  } else {
    name.value = ''
    description.value = ''
  }
}

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      resetForm()
    }
  },
  { immediate: true },
)

watch(
  () => props.group,
  () => {
    if (props.open) {
      resetForm()
    }
  },
)

async function handleSubmit() {
  if (!name.value.trim() || submitting.value) return

  submitting.value = true
  error.value = ''

  const body = {
    name: name.value.trim(),
    description: description.value.trim(),
  }

  const url = isEdit.value
    ? `/api/v1/orgs/${auth.activeOrgId}/groups/${props.group!.id}`
    : `/api/v1/orgs/${auth.activeOrgId}/groups`

  const method = isEdit.value ? 'PATCH' : 'POST'

  try {
    const resp = await fetch(url, {
      method,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-By': 'CVErt-Ops',
      },
      body: JSON.stringify(body),
    })

    if (!resp.ok) {
      const data = await resp.json()
      error.value = data.detail ?? 'Failed to save group'
      submitting.value = false
      return
    }

    const entry: GroupEntry = await resp.json()
    emit('saved', entry)
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
    @update:open="emit('update:open', $event)"
  >
    <DialogContent :show-close-button="true">
      <DialogHeader>
        <DialogTitle>{{ isEdit ? 'Edit Group' : 'Create Group' }}</DialogTitle>
        <DialogDescription>
          {{ isEdit ? 'Update the group name and description.' : 'Create a group to organize members.' }}
        </DialogDescription>
      </DialogHeader>

      <div class="space-y-4 py-2">
        <div class="space-y-2">
          <Label for="group-name">Name</Label>
          <Input
            id="group-name"
            v-model="name"
            data-testid="group-name-input"
            placeholder="Group name"
            :disabled="submitting"
            :aria-invalid="!!error || undefined"
            :aria-describedby="error ? 'group-error' : undefined"
          />
        </div>

        <div class="space-y-2">
          <Label for="group-description">Description</Label>
          <Input
            id="group-description"
            v-model="description"
            data-testid="group-description-input"
            placeholder="Optional description"
            :disabled="submitting"
          />
        </div>

        <p v-if="error" id="group-error" class="text-sm text-destructive" role="alert" data-testid="group-error">
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
          data-testid="group-submit-btn"
          :disabled="!name.trim() || submitting"
          @click="handleSubmit"
        >
          {{ submitting ? 'Saving...' : (isEdit ? 'Save' : 'Create') }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
