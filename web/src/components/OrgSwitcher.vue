<!-- ABOUTME: Dropdown to switch between the user's organizations. -->
<!-- ABOUTME: Reads from auth store and calls setActiveOrg on selection. -->

<script setup lang="ts">
import { ChevronsUpDown, Check } from 'lucide-vue-next'
import { useAuthStore } from '@/stores/auth'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

const auth = useAuthStore()
</script>

<template>
  <DropdownMenu>
    <DropdownMenuTrigger as-child>
      <button
        class="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-sm font-medium hover:bg-sidebar-accent"
        data-testid="org-switcher-trigger"
      >
        <span class="truncate">
          {{ auth.activeOrg?.name ?? 'Select org' }}
        </span>
        <ChevronsUpDown class="ml-1 size-4 shrink-0 text-muted-foreground" />
      </button>
    </DropdownMenuTrigger>
    <DropdownMenuContent class="w-56" align="start" side="bottom">
      <DropdownMenuLabel>Organizations</DropdownMenuLabel>
      <DropdownMenuSeparator />
      <DropdownMenuItem
        v-for="org in auth.user?.orgs ?? []"
        :key="org.org_id"
        class="flex items-center justify-between"
        @click="auth.setActiveOrg(org.org_id)"
      >
        <span class="truncate">{{ org.name }}</span>
        <Check
          v-if="auth.activeOrgId === org.org_id"
          class="ml-2 size-4 shrink-0"
        />
      </DropdownMenuItem>
    </DropdownMenuContent>
  </DropdownMenu>
</template>
