<!-- ABOUTME: Reusable error alert for displaying API or page errors. -->
<!-- ABOUTME: Shows error message with optional retry button. -->

<script setup lang="ts">
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

defineProps<{
  title?: string
  message: string
}>()

const emit = defineEmits<{
  retry: []
}>()
</script>

<template>
  <Alert variant="destructive">
    <AlertTitle>{{ title ?? 'Error' }}</AlertTitle>
    <AlertDescription class="flex items-center justify-between">
      <span>{{ message }}</span>
      <Button v-if="$attrs.onRetry" variant="outline" size="sm" @click="emit('retry')">
        Retry
      </Button>
    </AlertDescription>
  </Alert>
</template>
