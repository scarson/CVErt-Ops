<!-- ABOUTME: Site admin delivery management — list failed/stale deliveries with retry actions. -->
<!-- ABOUTME: Follows MembersView pattern — data table with status filter and bulk retry. -->

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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Loader2, RotateCcw } from 'lucide-vue-next'
import { toast } from 'vue-sonner'

interface DeliveryEntry {
  id: string
  org_id: string
  channel_type: string
  status: string
  attempts: number
  last_error?: string
  created_at: string
}

const deliveries = ref<DeliveryEntry[]>([])
const loading = ref(true)
const error = ref('')
const hasMore = ref(false)
const statusFilter = ref('failed')
const retrying = ref<string | null>(null)
const bulkRetrying = ref(false)

const STATUS_OPTIONS = ['failed', 'pending', 'sent', ''] as const
const STATUS_LABELS: Record<string, string> = {
  failed: 'Failed',
  pending: 'Pending',
  sent: 'Sent',
  '': 'All',
}

const statusBadgeVariant: Record<string, 'default' | 'destructive' | 'secondary'> = {
  sent: 'default',
  failed: 'destructive',
  pending: 'secondary',
}

async function fetchDeliveries() {
  loading.value = true
  error.value = ''

  try {
    const params = new URLSearchParams({ limit: '50' })
    if (statusFilter.value) {
      params.set('status', statusFilter.value)
    }
    const resp = await orgFetch(`/api/v1/admin/deliveries?${params}`)
    if (!resp.ok) {
      error.value = 'Failed to load deliveries.'
      loading.value = false
      return
    }

    const data = (await resp.json()) as { items: DeliveryEntry[]; has_more: boolean }
    deliveries.value = data.items ?? []
    hasMore.value = data.has_more
  } catch {
    error.value = 'Failed to load deliveries.'
  } finally {
    loading.value = false
  }
}

async function retryDelivery(id: string) {
  if (retrying.value) return
  retrying.value = id

  try {
    const resp = await orgFetch(`/api/v1/admin/deliveries/${id}/retry`, { method: 'POST' })
    if (resp.ok) {
      toast.success('Delivery retry enqueued')
      await fetchDeliveries()
    } else if (resp.status === 409) {
      toast.info('Delivery is not in a retryable state')
    } else {
      toast.error('Failed to retry delivery')
    }
  } catch {
    toast.error('Failed to retry delivery')
  } finally {
    retrying.value = null
  }
}

async function bulkRetryFailed() {
  if (bulkRetrying.value) return
  bulkRetrying.value = true

  try {
    const resp = await orgFetch('/api/v1/admin/deliveries/retry-failed', { method: 'POST' })
    if (resp.ok) {
      const data = (await resp.json()) as { rows_affected: number }
      toast.success(`${data.rows_affected} deliveries retried`)
      await fetchDeliveries()
    } else {
      toast.error('Failed to bulk retry deliveries')
    }
  } catch {
    toast.error('Failed to bulk retry deliveries')
  } finally {
    bulkRetrying.value = false
  }
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

function onStatusChange(val: string) {
  statusFilter.value = val
  fetchDeliveries()
}

onMounted(fetchDeliveries)
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold tracking-tight">Deliveries</h1>
        <p class="text-muted-foreground">Monitor and retry notification deliveries</p>
      </div>
      <div class="flex items-center gap-2">
        <Select :model-value="statusFilter" @update:model-value="(val) => onStatusChange(String(val ?? ''))">
          <SelectTrigger class="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem v-for="s in STATUS_OPTIONS" :key="s" :value="s">
              {{ STATUS_LABELS[s] }}
            </SelectItem>
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          :disabled="bulkRetrying"
          @click="bulkRetryFailed"
        >
          <Loader2
            v-if="bulkRetrying"
            class="mr-2 size-4 animate-spin"
            aria-hidden="true"
          />
          <RotateCcw v-else class="mr-2 size-4" aria-hidden="true" />
          Retry All Failed
        </Button>
      </div>
    </div>

    <div aria-live="polite">
      <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 class="mr-2 size-5 animate-spin" aria-hidden="true" />
        Loading deliveries...
      </div>

      <div v-else-if="error" class="py-16 text-center">
        <p class="text-sm text-destructive" role="alert">{{ error }}</p>
      </div>

      <div v-else-if="deliveries.length === 0" class="py-16 text-center">
        <p class="text-muted-foreground">No deliveries found.</p>
      </div>

      <Table v-else>
        <TableHeader>
          <TableRow>
            <TableHead>Channel</TableHead>
            <TableHead class="w-28">Status</TableHead>
            <TableHead class="w-20">Attempts</TableHead>
            <TableHead>Last Error</TableHead>
            <TableHead class="w-40">Created</TableHead>
            <TableHead class="w-20">
              <span class="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="d in deliveries" :key="d.id">
            <TableCell class="font-medium">{{ d.channel_type }}</TableCell>
            <TableCell>
              <Badge :variant="statusBadgeVariant[d.status] ?? 'secondary'">
                {{ d.status }}
              </Badge>
            </TableCell>
            <TableCell class="text-muted-foreground">{{ d.attempts }}</TableCell>
            <TableCell class="max-w-xs truncate text-sm text-muted-foreground">
              {{ d.last_error || '—' }}
            </TableCell>
            <TableCell class="text-muted-foreground">{{ formatDate(d.created_at) }}</TableCell>
            <TableCell>
              <Button
                v-if="d.status === 'failed'"
                variant="ghost"
                size="sm"
                :disabled="retrying === d.id"
                @click="retryDelivery(d.id)"
              >
                <Loader2
                  v-if="retrying === d.id"
                  class="size-4 animate-spin"
                  aria-hidden="true"
                />
                <RotateCcw v-else class="size-4" aria-hidden="true" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <div v-if="hasMore && !loading" class="flex justify-center pt-4">
        <p class="text-sm text-muted-foreground">More deliveries available. Pagination coming soon.</p>
      </div>
    </div>
  </div>
</template>
