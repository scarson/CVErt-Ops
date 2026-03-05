<!-- ABOUTME: 404 page for unknown routes. -->
<!-- ABOUTME: Shows a message and link back to the dashboard. -->

<script setup lang="ts">
import { Button } from '@/components/ui/button'
import { RouterLink } from 'vue-router'
</script>

<template>
  <div class="flex min-h-[50vh] flex-col items-center justify-center gap-4">
    <h1 class="text-4xl font-bold">404</h1>
    <p class="text-muted-foreground">Page not found</p>
    <Button as-child>
      <RouterLink to="/cves">Back to Dashboard</RouterLink>
    </Button>
  </div>
</template>
