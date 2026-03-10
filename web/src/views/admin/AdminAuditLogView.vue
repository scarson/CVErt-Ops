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
const error = ref('')
const hasMore = ref(false)
const entityTypeFilter = ref('')
const actionFilter = ref('')

async function fetchAuditLog() {
  loading.value = true
  error.value = ''

  try {
    const params = new URLSearchParams({ limit: '50' })
    if (entityTypeFilter.value) params.set('entity_type', entityTypeFilter.value)
    if (actionFilter.value) params.set('action', actionFilter.value)

    const resp = await orgFetch(`/api/v1/admin/audit-log?${params}`)
    if (!resp.ok) {
      error.value = 'Failed to load audit log.'
      loading.value = false
      return
    }

    const data = (await resp.json()) as { items: AuditEntry[]; has_more: boolean }
    entries.value = data.items ?? []
    hasMore.value = data.has_more
  } catch {
    error.value = 'Failed to load audit log.'
  } finally {
    loading.value = false
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

      <div v-if="hasMore && !loading" class="flex justify-center pt-4">
        <p class="text-sm text-muted-foreground">More entries available. Pagination coming soon.</p>
      </div>
    </div>
  </div>
</template>
