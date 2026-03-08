<!-- ABOUTME: User avatar and dropdown menu in the sidebar footer. -->
<!-- ABOUTME: Shows display name, email, and a logout option. -->

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { LogOut } from 'lucide-vue-next'
import { useAuthStore } from '@/stores/auth'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

const auth = useAuthStore()
const router = useRouter()

async function handleLogout() {
  await auth.logout()
  router.push('/login')
}

const initials = computed(() => {
  const name = auth.user?.display_name ?? ''
  return name
    .split(' ')
    .map((part) => part[0])
    .join('')
    .toUpperCase()
    .slice(0, 2)
})
</script>

<template>
  <DropdownMenu>
    <DropdownMenuTrigger as-child>
      <button
        class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-sidebar-accent"
        data-testid="user-menu-trigger"
      >
        <Avatar class="size-6">
          <AvatarFallback class="text-xs">{{ initials }}</AvatarFallback>
        </Avatar>
        <div class="flex min-w-0 flex-col items-start">
          <span class="truncate text-sm font-medium leading-tight">
            {{ auth.user?.display_name }}
          </span>
          <span class="truncate text-xs text-muted-foreground leading-tight">
            {{ auth.user?.email }}
          </span>
        </div>
      </button>
    </DropdownMenuTrigger>
    <DropdownMenuContent class="w-56" align="start" side="top">
      <DropdownMenuLabel class="font-normal">
        <div class="flex flex-col space-y-1">
          <p class="text-sm font-medium leading-none">
            {{ auth.user?.display_name }}
          </p>
          <p class="text-xs text-muted-foreground leading-none">
            {{ auth.user?.email }}
          </p>
        </div>
      </DropdownMenuLabel>
      <DropdownMenuSeparator />
      <DropdownMenuItem @click="handleLogout">
        <LogOut class="mr-2 size-4" aria-hidden="true" />
        Log out
      </DropdownMenuItem>
    </DropdownMenuContent>
  </DropdownMenu>
</template>
