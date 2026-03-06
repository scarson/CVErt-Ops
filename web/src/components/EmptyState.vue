<!-- ABOUTME: Reusable empty state component for pages with no data. -->
<!-- ABOUTME: Shows a message and optional action button. -->

<script setup lang="ts">
defineProps<{
  title: string
  description: string
}>()
</script>

<template>
  <div class="flex min-h-[30vh] flex-col items-center justify-center gap-3 text-center">
    <h3 class="text-lg font-medium">{{ title }}</h3>
    <p class="max-w-md text-sm text-muted-foreground">{{ description }}</p>
    <div v-if="$slots.action" class="mt-2">
      <slot name="action" />
    </div>
  </div>
</template>
