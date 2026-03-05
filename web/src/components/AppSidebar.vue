<!-- ABOUTME: Main sidebar navigation for authenticated pages. -->
<!-- ABOUTME: Renders nav sections (main, settings, admin) with route-aware active highlighting. -->

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, RouterLink } from 'vue-router'
import {
  Search,
  Eye,
  Users,
  FolderClosed,
  Activity,
} from 'lucide-vue-next'
import { Separator } from '@/components/ui/separator'
import OrgSwitcher from '@/components/OrgSwitcher.vue'
import UserMenu from '@/components/UserMenu.vue'

interface NavItem {
  label: string
  to: string
  icon: typeof Search
}

const mainNav: NavItem[] = [
  { label: 'CVE Search', to: '/cves', icon: Search },
  { label: 'Watchlists', to: '/watchlists', icon: Eye },
]

const settingsNav: NavItem[] = [
  { label: 'Members', to: '/settings/members', icon: Users },
  { label: 'Groups', to: '/settings/groups', icon: FolderClosed },
]

const adminNav: NavItem[] = [
  { label: 'Feed Status', to: '/admin/feeds', icon: Activity },
]

const route = useRoute()

function isActive(to: string): boolean {
  return route.path.startsWith(to)
}
</script>

<template>
  <aside
    class="flex h-full w-60 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground"
  >
    <!-- Header: org switcher -->
    <div class="flex h-14 items-center border-b border-sidebar-border px-3">
      <OrgSwitcher />
    </div>

    <!-- Navigation -->
    <nav class="flex-1 overflow-y-auto px-3 py-2">
      <!-- Main section -->
      <div class="space-y-0.5">
        <span class="mb-1 block px-2 text-xs font-medium text-muted-foreground">
          Main
        </span>
        <RouterLink
          v-for="item in mainNav"
          :key="item.to"
          :to="item.to"
          class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors"
          :class="
            isActive(item.to)
              ? 'bg-sidebar-accent text-sidebar-accent-foreground font-medium'
              : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground'
          "
        >
          <component :is="item.icon" class="size-4 shrink-0" />
          {{ item.label }}
        </RouterLink>
      </div>

      <Separator class="my-3" />

      <!-- Settings section -->
      <div class="space-y-0.5">
        <span class="mb-1 block px-2 text-xs font-medium text-muted-foreground">
          Settings
        </span>
        <RouterLink
          v-for="item in settingsNav"
          :key="item.to"
          :to="item.to"
          class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors"
          :class="
            isActive(item.to)
              ? 'bg-sidebar-accent text-sidebar-accent-foreground font-medium'
              : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground'
          "
        >
          <component :is="item.icon" class="size-4 shrink-0" />
          {{ item.label }}
        </RouterLink>
      </div>

      <Separator class="my-3" />

      <!-- Admin section -->
      <div class="space-y-0.5">
        <span class="mb-1 block px-2 text-xs font-medium text-muted-foreground">
          Admin
        </span>
        <RouterLink
          v-for="item in adminNav"
          :key="item.to"
          :to="item.to"
          class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors"
          :class="
            isActive(item.to)
              ? 'bg-sidebar-accent text-sidebar-accent-foreground font-medium'
              : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground'
          "
        >
          <component :is="item.icon" class="size-4 shrink-0" />
          {{ item.label }}
        </RouterLink>
      </div>
    </nav>

    <!-- Footer: user menu -->
    <div class="border-t border-sidebar-border px-3 py-2">
      <UserMenu />
    </div>
  </aside>
</template>
