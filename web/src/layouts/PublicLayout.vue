<!-- ABOUTME: Layout for unauthenticated pages (login, register, invitation). -->
<!-- ABOUTME: Minimal centered layout with the app logo/name. -->

<script setup lang="ts">
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-background">
    <div class="w-full max-w-md space-y-6 px-4">
      <div class="text-center">
        <h1 class="text-2xl font-bold tracking-tight">CVErt Ops</h1>
        <p class="text-sm text-muted-foreground">Vulnerability Intelligence</p>
      </div>
      <slot />
    </div>
  </div>
</template>
