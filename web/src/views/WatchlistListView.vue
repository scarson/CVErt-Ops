<!-- ABOUTME: Watchlist listing page — shows all org watchlists with create and delete. -->
<!-- ABOUTME: Fetches via raw fetch(); supports empty, loading, and error states. -->

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import CreateWatchlistDialog from '@/components/watchlist/CreateWatchlistDialog.vue'
import type { WatchlistEntry } from '@/components/watchlist/CreateWatchlistDialog.vue'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Plus, Trash2, FileText, Loader2 } from 'lucide-vue-next'

const auth = useAuthStore()

const watchlists = ref<WatchlistEntry[]>([])
const loading = ref(true)
const error = ref('')
const createDialogOpen = ref(false)
const deleteTarget = ref<WatchlistEntry | null>(null)
const deleteDialogOpen = ref(false)
const deleting = ref(false)
const deleteError = ref('')

function apiBase() {
  return `/api/v1/orgs/${auth.activeOrgId}/watchlists`
}

async function fetchWatchlists() {
  loading.value = true
  error.value = ''

  try {
    const resp = await fetch(apiBase(), {
      method: 'GET',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    })

    if (!resp.ok) {
      error.value = 'Failed to load watchlists. Please try again.'
      loading.value = false
      return
    }

    const data = await resp.json() as { items?: WatchlistEntry[] }
    watchlists.value = data.items ?? []
  } catch {
    error.value = 'Failed to load watchlists. Please try again.'
  } finally {
    loading.value = false
  }
}

function onWatchlistCreated(entry: WatchlistEntry) {
  watchlists.value = [...watchlists.value, entry]
}

function promptDelete(wl: WatchlistEntry) {
  deleteTarget.value = wl
  deleteError.value = ''
  deleteDialogOpen.value = true
}

async function confirmDelete() {
  if (!deleteTarget.value || deleting.value) return

  deleting.value = true
  deleteError.value = ''
  const id = deleteTarget.value.id

  try {
    const resp = await fetch(`${apiBase()}/${id}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-By': 'CVErt-Ops',
      },
    })

    if (resp.ok) {
      watchlists.value = watchlists.value.filter((w) => w.id !== id)
      deleteDialogOpen.value = false
      deleteTarget.value = null
    } else {
      deleteError.value = 'Failed to delete watchlist. Please try again.'
    }
  } catch {
    deleteError.value = 'Failed to delete watchlist. Please try again.'
  } finally {
    deleting.value = false
  }
}

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60_000)
  const diffHours = Math.floor(diffMs / 3_600_000)
  const diffDays = Math.floor(diffMs / 86_400_000)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`
  if (diffDays < 30) return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`

  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function truncate(text: string | undefined, max: number): string {
  if (!text) return ''
  if (text.length <= max) return text
  return text.slice(0, max) + '...'
}

onMounted(() => {
  fetchWatchlists()
})

watch(
  () => auth.activeOrgId,
  () => {
    fetchWatchlists()
  },
)
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">Watchlists</h1>
        <p class="text-sm text-muted-foreground">
          Track packages and products for vulnerability monitoring
        </p>
      </div>
      <Button
        data-testid="new-watchlist-btn"
        @click="createDialogOpen = true"
      >
        <Plus class="mr-2 size-4" />
        New Watchlist
      </Button>
    </div>

    <!-- Loading state -->
    <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
      <Loader2 class="mr-2 size-5 animate-spin" />
      Loading watchlists...
    </div>

    <!-- Error state -->
    <div v-else-if="error" class="py-16 text-center">
      <p class="text-sm text-destructive">{{ error }}</p>
    </div>

    <!-- Empty state -->
    <Card v-else-if="watchlists.length === 0" class="py-16">
      <CardContent class="flex flex-col items-center text-center">
        <FileText class="mb-4 size-12 text-muted-foreground" />
        <h2 class="text-lg font-semibold">No watchlists yet</h2>
        <p class="mt-1 text-sm text-muted-foreground">
          Create your first watchlist to start tracking vulnerabilities
        </p>
        <Button
          class="mt-4"
          data-testid="empty-create-btn"
          @click="createDialogOpen = true"
        >
          <Plus class="mr-2 size-4" />
          New Watchlist
        </Button>
      </CardContent>
    </Card>

    <!-- Watchlists table -->
    <Table v-else>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Description</TableHead>
          <TableHead class="w-24 text-right">Items</TableHead>
          <TableHead class="w-40">Last Updated</TableHead>
          <TableHead class="w-16" />
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="wl in watchlists" :key="wl.id">
          <TableCell class="font-medium">
            <RouterLink
              :to="`/watchlists/${wl.id}`"
              class="underline underline-offset-4 hover:text-foreground"
            >
              {{ wl.name }}
            </RouterLink>
          </TableCell>
          <TableCell data-testid="watchlist-description" class="text-muted-foreground">
            {{ truncate(wl.description, 100) }}
          </TableCell>
          <TableCell class="text-right">{{ wl.item_count }}</TableCell>
          <TableCell class="text-muted-foreground">
            {{ formatRelativeTime(wl.updated_at) }}
          </TableCell>
          <TableCell>
            <Button
              variant="ghost"
              size="sm"
              data-testid="delete-watchlist-btn"
              @click="promptDelete(wl)"
            >
              <Trash2 class="size-4 text-destructive" />
            </Button>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>

    <!-- Create dialog -->
    <CreateWatchlistDialog
      :open="createDialogOpen"
      data-testid="create-watchlist-dialog"
      @update:open="createDialogOpen = $event"
      @created="onWatchlistCreated"
    />

    <!-- Delete confirmation dialog -->
    <AlertDialog :open="deleteDialogOpen" @update:open="deleteDialogOpen = $event">
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Are you sure?</AlertDialogTitle>
          <AlertDialogDescription>
            This will permanently delete the watchlist and all its items.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <p v-if="deleteError" class="text-sm text-destructive">{{ deleteError }}</p>
        <AlertDialogFooter>
          <AlertDialogCancel :disabled="deleting" @click="deleteDialogOpen = false">Cancel</AlertDialogCancel>
          <Button
            data-testid="confirm-delete-btn"
            variant="destructive"
            :disabled="deleting"
            @click="confirmDelete"
          >
            {{ deleting ? 'Deleting...' : 'Delete' }}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  </div>
</template>
