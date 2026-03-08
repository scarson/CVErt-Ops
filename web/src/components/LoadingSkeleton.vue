<!-- ABOUTME: Reusable loading skeleton for page-level loading states. -->
<!-- ABOUTME: Renders a configurable number of skeleton rows. -->

<script setup lang="ts">
import { Skeleton } from '@/components/ui/skeleton'

withDefaults(defineProps<{
  rows?: number
}>(), {
  rows: 5,
})
</script>

<template>
  <div class="space-y-4">
    <Skeleton class="h-8 w-48" />
    <Skeleton class="h-4 w-64" />
    <div class="mt-6 space-y-3">
      <Skeleton v-for="i in rows" :key="i" class="h-12 w-full" />
    </div>
  </div>
</template>
