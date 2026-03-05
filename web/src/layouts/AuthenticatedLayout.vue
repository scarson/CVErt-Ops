<!-- ABOUTME: Primary layout for all authenticated pages. -->
<!-- ABOUTME: Fixed sidebar on desktop, sheet/drawer on mobile, with main content slot. -->

<script setup lang="ts">
import { ref } from 'vue'
import { Menu } from 'lucide-vue-next'
import { Button } from '@/components/ui/button'
import {
  Sheet,
  SheetContent,
  SheetTitle,
} from '@/components/ui/sheet'
import AppSidebar from '@/components/AppSidebar.vue'

const mobileOpen = ref(false)
</script>

<template>
  <div class="flex h-screen overflow-hidden bg-background">
    <!-- Desktop sidebar (hidden on small screens) -->
    <div class="hidden md:flex">
      <AppSidebar />
    </div>

    <!-- Mobile sheet trigger + content area -->
    <div class="flex flex-1 flex-col overflow-hidden">
      <!-- Mobile header bar -->
      <header class="flex h-14 items-center border-b px-4 md:hidden">
        <Sheet v-model:open="mobileOpen">
          <Button
            variant="ghost"
            size="icon"
            class="-ml-2"
            @click="mobileOpen = true"
          >
            <Menu class="size-5" />
            <span class="sr-only">Open navigation</span>
          </Button>
          <SheetContent side="left" class="w-60 p-0">
            <SheetTitle class="sr-only">Navigation</SheetTitle>
            <AppSidebar />
          </SheetContent>
        </Sheet>
        <span class="ml-2 text-sm font-semibold">CVErt Ops</span>
      </header>

      <!-- Main content -->
      <main class="flex-1 overflow-y-auto">
        <slot />
      </main>
    </div>
  </div>
</template>
