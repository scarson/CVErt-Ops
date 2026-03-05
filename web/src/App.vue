<!-- ABOUTME: Root application component with dynamic layout switching. -->
<!-- ABOUTME: Selects PublicLayout or AuthenticatedLayout based on route meta. -->

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import PublicLayout from '@/layouts/PublicLayout.vue'
import AuthenticatedLayout from '@/layouts/AuthenticatedLayout.vue'
import { Toaster } from '@/components/ui/sonner'

const route = useRoute()

const layout = computed(() => {
  return route.meta.layout === 'public' ? PublicLayout : AuthenticatedLayout
})
</script>

<template>
  <component :is="layout">
    <RouterView />
  </component>
  <Toaster />
</template>
