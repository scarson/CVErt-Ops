<!-- ABOUTME: Watchlist detail page — shows items in a watchlist. -->
<!-- ABOUTME: Supports adding/removing items and editing watchlist name/description inline. -->

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRoute, useRouter, RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import type { WatchlistEntry } from '@/components/watchlist/CreateWatchlistDialog.vue'
import AddItemDialog from '@/components/watchlist/AddItemDialog.vue'
import type { WatchlistItemEntry } from '@/components/watchlist/AddItemDialog.vue'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
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
  ArrowLeft,
  Trash2,
  Plus,
  Pencil,
  Check,
  X,
  Package,
  Cpu,
  Loader2,
} from 'lucide-vue-next'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const watchlist = ref<WatchlistEntry | null>(null)
const items = ref<WatchlistItemEntry[]>([])
const loading = ref(true)
const notFound = ref(false)
const error = ref('')
const addDialogOpen = ref(false)

// Inline edit state
const editingName = ref(false)
const editName = ref('')
const editDescription = ref('')
const saving = ref(false)

function apiBase() {
  return `/api/v1/orgs/${auth.activeOrgId}/watchlists/${route.params.id}`
}

async function fetchWatchlist() {
  error.value = ''

  try {
    const resp = await fetch(apiBase(), {
      method: 'GET',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    })

    if (!resp.ok) {
      if (resp.status === 404) {
        notFound.value = true
      } else {
        error.value = 'Failed to load watchlist. Please try again.'
      }
      loading.value = false
      return
    }

    watchlist.value = await resp.json() as WatchlistEntry
  } catch {
    error.value = 'Failed to load watchlist. Please try again.'
    loading.value = false
  }
}

async function fetchItems() {
  try {
    const resp = await fetch(`${apiBase()}/items`, {
      method: 'GET',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    })

    if (resp.ok) {
      const data = await resp.json() as { items?: WatchlistItemEntry[] }
      items.value = data.items ?? []
    }
  } finally {
    loading.value = false
  }
}

function startEditName() {
  if (!watchlist.value) return
  editingName.value = true
  editName.value = watchlist.value.name
  editDescription.value = watchlist.value.description ?? ''
}

function cancelEditName() {
  editingName.value = false
}

async function saveName() {
  if (!watchlist.value || saving.value) return

  saving.value = true

  const body: Record<string, string> = {}
  if (editName.value.trim() !== watchlist.value.name) {
    body.name = editName.value.trim()
  }
  if (editDescription.value.trim() !== (watchlist.value.description ?? '')) {
    body.description = editDescription.value.trim()
  }

  // Nothing changed
  if (Object.keys(body).length === 0) {
    editingName.value = false
    saving.value = false
    return
  }

  try {
    const resp = await fetch(apiBase(), {
      method: 'PATCH',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-By': 'CVErt-Ops',
      },
      body: JSON.stringify(body),
    })

    if (resp.ok) {
      watchlist.value = await resp.json() as WatchlistEntry
    }
  } finally {
    editingName.value = false
    saving.value = false
  }
}

async function deleteItem(itemId: string) {
  try {
    const resp = await fetch(`${apiBase()}/items/${itemId}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-By': 'CVErt-Ops',
      },
    })

    if (resp.ok) {
      items.value = items.value.filter((i) => i.id !== itemId)
    }
  } catch {
    // Silently fail — item stays in the list
  }
}

function onItemAdded(item: WatchlistItemEntry) {
  items.value = [...items.value, item]
}

function formatIdentifier(item: WatchlistItemEntry): string {
  if (item.item_type === 'package') {
    return `${item.ecosystem}/${item.package_name}`
  }
  return item.cpe_normalized ?? ''
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

onMounted(async () => {
  await fetchWatchlist()
  if (watchlist.value) {
    await fetchItems()
  }
})

watch(
  () => auth.activeOrgId,
  () => {
    router.push('/watchlists')
  },
)
</script>

<template>
  <div class="space-y-6">
    <!-- Loading state -->
    <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
      <Loader2 class="mr-2 size-5 animate-spin" />
      Loading watchlist...
    </div>

    <!-- Not found state -->
    <div v-else-if="notFound" class="py-16 text-center">
      <h2 class="text-lg font-semibold">Watchlist not found</h2>
      <p class="text-muted-foreground mt-2 text-sm">
        The watchlist you're looking for doesn't exist or you don't have access.
      </p>
      <RouterLink to="/watchlists" class="text-primary mt-4 inline-block text-sm underline">
        Back to Watchlists
      </RouterLink>
    </div>

    <!-- Error state -->
    <div v-else-if="error" class="py-16 text-center">
      <p class="text-sm text-destructive">{{ error }}</p>
    </div>

    <!-- Loaded state -->
    <template v-else-if="watchlist">
      <!-- Back link -->
      <RouterLink
        to="/watchlists"
        class="text-muted-foreground hover:text-foreground inline-flex items-center text-sm"
      >
        <ArrowLeft class="mr-1 size-4" />
        Back to Watchlists
      </RouterLink>

      <!-- Header -->
      <div class="space-y-2">
        <!-- Name display / edit -->
        <div v-if="!editingName" class="flex items-center gap-2">
          <h1 class="text-2xl font-semibold tracking-tight" data-testid="watchlist-name">
            {{ watchlist.name }}
          </h1>
          <Button
            variant="ghost"
            size="sm"
            data-testid="edit-name-btn"
            @click="startEditName"
          >
            <Pencil class="size-4" />
          </Button>
        </div>

        <!-- Name edit mode -->
        <div v-else class="space-y-3">
          <div class="flex items-center gap-2">
            <Input
              v-model="editName"
              data-testid="edit-name-input"
              class="max-w-sm text-lg font-semibold"
              :disabled="saving"
            />
            <Button
              variant="ghost"
              size="sm"
              data-testid="save-name-btn"
              :disabled="saving"
              @click="saveName"
            >
              <Check class="size-4" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              data-testid="cancel-name-btn"
              :disabled="saving"
              @click="cancelEditName"
            >
              <X class="size-4" />
            </Button>
          </div>
          <Input
            v-model="editDescription"
            data-testid="edit-description-input"
            placeholder="Description (optional)"
            class="max-w-sm"
            :disabled="saving"
          />
        </div>

        <!-- Description display -->
        <p
          v-if="!editingName && watchlist.description"
          class="text-muted-foreground text-sm"
          data-testid="watchlist-description"
        >
          {{ watchlist.description }}
        </p>
      </div>

      <!-- Items section -->
      <div class="flex items-center justify-between">
        <h2 class="text-lg font-medium">Items</h2>
        <Button
          data-testid="add-item-btn-trigger"
          size="sm"
          @click="addDialogOpen = true"
        >
          <Plus class="mr-1 size-4" />
          Add Item
        </Button>
      </div>

      <!-- Empty items state -->
      <Card v-if="items.length === 0" class="py-12">
        <CardContent class="flex flex-col items-center text-center">
          <Package class="text-muted-foreground mb-4 size-10" />
          <p class="font-medium">No items in this watchlist</p>
          <p class="text-muted-foreground mt-1 text-sm">
            Add packages or CPE patterns to monitor
          </p>
        </CardContent>
      </Card>

      <!-- Items table -->
      <Table v-else>
        <TableHeader>
          <TableRow>
            <TableHead class="w-24">Type</TableHead>
            <TableHead>Identifier</TableHead>
            <TableHead class="w-36">Added</TableHead>
            <TableHead class="w-16" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="item in items" :key="item.id" :data-testid="`item-row-${item.id}`">
            <TableCell>
              <Badge
                :variant="item.item_type === 'package' ? 'default' : 'secondary'"
                data-testid="item-type-badge"
              >
                <Package v-if="item.item_type === 'package'" class="mr-1 size-3" />
                <Cpu v-else class="mr-1 size-3" />
                {{ item.item_type }}
              </Badge>
            </TableCell>
            <TableCell class="font-mono text-sm" data-testid="item-identifier">
              {{ formatIdentifier(item) }}
            </TableCell>
            <TableCell class="text-muted-foreground text-sm">
              {{ formatDate(item.created_at) }}
            </TableCell>
            <TableCell>
              <Button
                variant="ghost"
                size="sm"
                data-testid="delete-item-btn"
                @click="deleteItem(item.id)"
              >
                <Trash2 class="size-4 text-destructive" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </template>

    <!-- Add Item Dialog -->
    <AddItemDialog
      :open="addDialogOpen"
      :watchlist-id="(route.params.id as string)"
      @update:open="addDialogOpen = $event"
      @added="onItemAdded"
    />
  </div>
</template>
