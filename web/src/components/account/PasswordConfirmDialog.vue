<!-- ABOUTME: Dialog that asks for the current password before a sensitive account change. -->
<!-- ABOUTME: Emits 'confirm' with the password; the parent performs the request and passes back any error. -->

<script setup lang="ts">
import { ref, watch } from 'vue'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const props = defineProps<{
  open: boolean
  title: string
  description: string
  confirmLabel: string
  busy: boolean
  error: string
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
  confirm: [password: string]
}>()

const password = ref('')

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) password.value = ''
  },
)

function onSubmit() {
  if (!password.value || props.busy) return
  emit('confirm', password.value)
}
</script>

<template>
  <Dialog :open="props.open" @update:open="emit('update:open', $event)">
    <DialogContent :show-close-button="true">
      <DialogHeader>
        <DialogTitle>{{ props.title }}</DialogTitle>
        <DialogDescription>{{ props.description }}</DialogDescription>
      </DialogHeader>
      <form class="space-y-4" data-testid="password-confirm-form" @submit.prevent="onSubmit">
        <div class="space-y-2">
          <Label for="confirm-current-password">Current password</Label>
          <Input
            id="confirm-current-password"
            v-model="password"
            type="password"
            autocomplete="current-password"
            required
            :aria-invalid="!!props.error || undefined"
            :aria-describedby="props.error ? 'password-confirm-error' : undefined"
          />
        </div>
        <p v-if="props.error" id="password-confirm-error" class="text-sm text-destructive" role="alert">
          {{ props.error }}
        </p>
        <DialogFooter>
          <Button type="button" variant="outline" :disabled="props.busy" @click="emit('update:open', false)">
            Cancel
          </Button>
          <Button type="submit" data-testid="password-confirm-submit" :disabled="props.busy">
            {{ props.busy ? 'Working...' : props.confirmLabel }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
