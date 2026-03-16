<!-- ABOUTME: Site admin cross-org audit log viewer with filtering. -->
<!-- ABOUTME: Follows CVE search pattern — data table with filter controls and keyset pagination. -->

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { orgFetch } from '@/lib/api/orgFetch'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Loader2, Search } from 'lucide-vue-next'

interface AuditEntry {
  id: string
  org_id?: string
  actor_id?: string
  actor_email?: string
  entity_type: string
  entity_id: string
  action: string
  success: boolean
  created_at: string
}

const entries = ref<AuditEntry[]>([])
const loading = ref(true)
const loadingMore = ref(false)
const error = ref('')
const nextCursor = ref<string | undefined>()
const entityTypeFilter = ref('')
const actionFilter = ref('')

async function fetchAuditLog(cursor?: string) {
  if (cursor) {
    loadingMore.value = true
  } else {
    loading.value = true
  }
  error.value = ''

  try {
    const params = new URLSearchParams({ limit: '50' })
    if (entityTypeFilter.value) params.set('entity_type', entityTypeFilter.value)
    if (actionFilter.value) params.set('action', actionFilter.value)
    if (cursor) params.set('cursor', cursor)

    const resp = await orgFetch(`/api/v1/admin/audit-log?${params}`)
    if (!resp.ok) {
      error.value = 'Failed to load audit log.'
      return
    }

    const data = (await resp.json()) as { items: AuditEntry[]; next_cursor?: string }
    if (cursor) {
      entries.value = [...entries.value, ...(data.items ?? [])]
    } else {
      entries.value = data.items ?? []
    }
    nextCursor.value = data.next_cursor
  } catch {
    error.value = 'Failed to load audit log.'
  } finally {
    loading.value = false
    loadingMore.value = false
  }
}

function applyFilters() {
  fetchAuditLog()
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function actionBadgeVariant(action: string): 'default' | 'destructive' | 'secondary' {
  if (action.startsWith('delete') || action.startsWith('remove')) return 'destructive'
  if (action.startsWith('create') || action.startsWith('add')) return 'default'
  return 'secondary'
}

onMounted(fetchAuditLog)
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold tracking-tight">Audit Log</h1>
      <p class="text-muted-foreground">Cross-organization activity log</p>
    </div>

    <!-- Filters -->
    <div class="flex items-center gap-2">
      <Input
        v-model="entityTypeFilter"
        placeholder="Entity type..."
        class="w-40"
        @keyup.enter="applyFilters"
      />
      <Input
        v-model="actionFilter"
        placeholder="Action..."
        class="w-40"
        @keyup.enter="applyFilters"
      />
      <Button variant="outline" size="sm" @click="applyFilters">
        <Search class="mr-1 size-4" aria-hidden="true" />
        Filter
      </Button>
    </div>

    <div aria-live="polite">
      <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 class="mr-2 size-5 animate-spin" aria-hidden="true" />
        Loading audit log...
      </div>

      <div v-else-if="error" class="py-16 text-center">
        <p class="text-sm text-destructive" role="alert">{{ error }}</p>
      </div>

      <div v-else-if="entries.length === 0" class="py-16 text-center">
        <p class="text-muted-foreground">No audit log entries found.</p>
      </div>

      <Table v-else>
        <TableHeader>
          <TableRow>
            <TableHead class="w-40">Time</TableHead>
            <TableHead>Actor</TableHead>
            <TableHead class="w-28">Entity Type</TableHead>
            <TableHead class="w-28">Action</TableHead>
            <TableHead>Entity ID</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="entry in entries" :key="entry.id">
            <TableCell class="text-muted-foreground">
              {{ formatDate(entry.created_at) }}
            </TableCell>
            <TableCell class="font-medium">
              {{ entry.actor_email || entry.actor_id || 'System' }}
            </TableCell>
            <TableCell>
              <Badge variant="outline">{{ entry.entity_type }}</Badge>
            </TableCell>
            <TableCell>
              <Badge :variant="actionBadgeVariant(entry.action)">
                {{ entry.action }}
              </Badge>
            </TableCell>
            <TableCell class="max-w-xs truncate text-sm text-muted-foreground">
              {{ entry.entity_id }}
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <div v-if="nextCursor && !loading" class="flex justify-center pt-4">
        <Button variant="outline" :disabled="loadingMore" @click="fetchAuditLog(nextCursor)">
          <Loader2 v-if="loadingMore" class="mr-2 size-4 animate-spin" aria-hidden="true" />
          Load More
        </Button>
      </div>
    </div>
  </div>
</template>
