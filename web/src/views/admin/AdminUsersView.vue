<!-- ABOUTME: Site admin user management — list users with disable/enable, unlock, and password reset actions. -->
<!-- ABOUTME: Follows MembersView pattern — data table with status badges and action buttons. -->

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { orgFetch } from '@/lib/api/orgFetch'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Loader2, MoreHorizontal } from 'lucide-vue-next'
import { toast } from 'vue-sonner'

interface UserEntry {
  id: string
  email: string
  display_name: string
  is_site_admin: boolean
  disabled_at?: string | null
  locked_at?: string | null
  force_password_reset: boolean
  created_at: string
}

const users = ref<UserEntry[]>([])
const loading = ref(true)
const loadingMore = ref(false)
const error = ref('')
const nextCursor = ref<string | undefined>()

async function fetchUsers(cursor?: string) {
  if (cursor) {
    loadingMore.value = true
  } else {
    loading.value = true
  }
  error.value = ''

  try {
    const params = new URLSearchParams({ limit: '50' })
    if (cursor) params.set('cursor', cursor)

    const resp = await orgFetch(`/api/v1/admin/users?${params}`)
    if (!resp.ok) {
      error.value = 'Failed to load users.'
      return
    }

    const data = (await resp.json()) as { items: UserEntry[]; next_cursor?: string }
    if (cursor) {
      users.value = [...users.value, ...(data.items ?? [])]
    } else {
      users.value = data.items ?? []
    }
    nextCursor.value = data.next_cursor
  } catch {
    error.value = 'Failed to load users.'
  } finally {
    loading.value = false
    loadingMore.value = false
  }
}

async function toggleDisable(user: UserEntry) {
  const action = user.disabled_at ? 'enable' : 'disable'
  try {
    const resp = await orgFetch(`/api/v1/admin/users/${user.id}/${action}`, {
      method: 'POST',
    })
    if (resp.ok) {
      toast.success(`User ${action}d`)
      await fetchUsers()
    } else {
      const body = await resp.text()
      toast.error(body || `Failed to ${action} user`)
    }
  } catch {
    toast.error(`Failed to ${action} user`)
  }
}

async function unlockUser(userId: string) {
  try {
    const resp = await orgFetch(`/api/v1/admin/users/${userId}/unlock`, {
      method: 'POST',
    })
    if (resp.ok) {
      toast.success('User unlocked')
      await fetchUsers()
    } else {
      toast.error('Failed to unlock user')
    }
  } catch {
    toast.error('Failed to unlock user')
  }
}

async function forcePasswordReset(userId: string) {
  try {
    const resp = await orgFetch(`/api/v1/admin/users/${userId}/reset-password`, {
      method: 'POST',
    })
    if (resp.ok) {
      toast.success('Password reset required on next login')
      await fetchUsers()
    } else {
      toast.error('Failed to force password reset')
    }
  } catch {
    toast.error('Failed to force password reset')
  }
}

function userStatus(user: UserEntry): { label: string; variant: 'default' | 'destructive' | 'secondary' } {
  if (user.disabled_at) return { label: 'Disabled', variant: 'destructive' }
  if (user.locked_at) return { label: 'Locked', variant: 'secondary' }
  return { label: 'Active', variant: 'default' }
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

onMounted(fetchUsers)
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold tracking-tight">Users</h1>
      <p class="text-muted-foreground">Manage all user accounts</p>
    </div>

    <div aria-live="polite">
      <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 class="mr-2 size-5 animate-spin" aria-hidden="true" />
        Loading users...
      </div>

      <div v-else-if="error" class="py-16 text-center">
        <p class="text-sm text-destructive" role="alert">{{ error }}</p>
      </div>

      <Table v-else>
        <TableHeader>
          <TableRow>
            <TableHead>Email</TableHead>
            <TableHead>Name</TableHead>
            <TableHead class="w-28">Status</TableHead>
            <TableHead class="w-24">Role</TableHead>
            <TableHead class="w-32">Created</TableHead>
            <TableHead class="w-16">
              <span class="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="u in users" :key="u.id">
            <TableCell class="font-medium">{{ u.email }}</TableCell>
            <TableCell class="text-muted-foreground">{{ u.display_name }}</TableCell>
            <TableCell>
              <div class="flex items-center gap-1">
                <Badge :variant="userStatus(u).variant">
                  {{ userStatus(u).label }}
                </Badge>
                <Badge v-if="u.force_password_reset" variant="secondary" class="text-xs">
                  Reset
                </Badge>
              </div>
            </TableCell>
            <TableCell>
              <Badge v-if="u.is_site_admin" variant="default">Admin</Badge>
              <span v-else class="text-muted-foreground">User</span>
            </TableCell>
            <TableCell class="text-muted-foreground">{{ formatDate(u.created_at) }}</TableCell>
            <TableCell>
              <DropdownMenu>
                <DropdownMenuTrigger as-child>
                  <Button variant="ghost" size="sm" aria-label="User actions">
                    <MoreHorizontal class="size-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem @click="toggleDisable(u)">
                    {{ u.disabled_at ? 'Enable' : 'Disable' }}
                  </DropdownMenuItem>
                  <DropdownMenuItem v-if="u.locked_at" @click="unlockUser(u.id)">
                    Unlock
                  </DropdownMenuItem>
                  <DropdownMenuItem @click="forcePasswordReset(u.id)">
                    Force Password Reset
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <div v-if="nextCursor && !loading" class="flex justify-center pt-4">
        <Button variant="outline" :disabled="loadingMore" @click="fetchUsers(nextCursor)">
          <Loader2 v-if="loadingMore" class="mr-2 size-4 animate-spin" aria-hidden="true" />
          Load More
        </Button>
      </div>
    </div>
  </div>
</template>
