<!-- ABOUTME: Site admin feed status page with pause/resume controls and log viewer. -->
<!-- ABOUTME: Extends the FeedStatusView pattern with admin-specific actions. -->

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import client from '@/lib/api/client'
import { Button } from '@/components/ui/button'
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
import { Loader2, Play, Pause, RotateCcw, ChevronDown, ChevronRight } from 'lucide-vue-next'
import { toast } from 'vue-sonner'

interface FeedLogEntry {
  id: string
  started_at: string
  ended_at?: string
  status: string
  items_fetched: number
  items_upserted: number
  error_summary?: string
}

interface FeedEntry {
  feed_name: string
  last_success_at?: string
  last_attempt_at?: string
  consecutive_failures: number
  last_error?: string
  backoff_until?: string
  paused_at?: string | null
  recent_logs: FeedLogEntry[]
}

const feeds = ref<FeedEntry[]>([])
const loading = ref(true)
const error = ref('')
const actionInProgress = ref<string | null>(null)
const expandedFeed = ref<string | null>(null)

async function fetchFeeds() {
  loading.value = true
  error.value = ''

  try {
    const { data, error: fetchError } = await client.GET('/admin/feeds')
    if (fetchError) {
      error.value = 'Failed to load feed status.'
      loading.value = false
      return
    }

    feeds.value = (data.items ?? []).map((f) => ({
      ...f,
      recent_logs: f.recent_logs ?? [],
    }))
  } catch {
    error.value = 'Failed to load feed status.'
  } finally {
    loading.value = false
  }
}

async function triggerFeed(feedName: string) {
  if (actionInProgress.value) return
  actionInProgress.value = feedName

  try {
    const { error: fetchError } = await client.POST('/admin/feeds/{feed}/run', {
      params: { path: { feed: feedName } },
    })
    if (fetchError?.status === 409) {
      toast.info('Job already pending for ' + feedName)
    } else if (!fetchError) {
      toast.success('Job enqueued for ' + feedName)
      await fetchFeeds()
    } else {
      toast.error('Failed to trigger ' + feedName)
    }
  } catch {
    toast.error('Failed to trigger ' + feedName)
  } finally {
    actionInProgress.value = null
  }
}

async function pauseFeed(feedName: string) {
  if (actionInProgress.value) return
  actionInProgress.value = feedName

  try {
    const { error: fetchError } = await client.POST('/admin/feeds/{feed}/pause', {
      params: { path: { feed: feedName } },
    })
    if (!fetchError) {
      toast.success(feedName + ' paused')
      await fetchFeeds()
    } else {
      toast.error('Failed to pause ' + feedName)
    }
  } catch {
    toast.error('Failed to pause ' + feedName)
  } finally {
    actionInProgress.value = null
  }
}

async function resumeFeed(feedName: string) {
  if (actionInProgress.value) return
  actionInProgress.value = feedName

  try {
    const { error: fetchError } = await client.POST('/admin/feeds/{feed}/resume', {
      params: { path: { feed: feedName } },
    })
    if (!fetchError) {
      toast.success(feedName + ' resumed')
      await fetchFeeds()
    } else {
      toast.error('Failed to resume ' + feedName)
    }
  } catch {
    toast.error('Failed to resume ' + feedName)
  } finally {
    actionInProgress.value = null
  }
}

function statusBadge(feed: FeedEntry): { label: string; variant: 'default' | 'destructive' | 'secondary' } {
  if (feed.paused_at) return { label: 'Paused', variant: 'secondary' }
  if (feed.consecutive_failures > 0) return { label: 'Failing', variant: 'destructive' }
  if (feed.last_success_at) return { label: 'Healthy', variant: 'default' }
  return { label: 'Never Synced', variant: 'secondary' }
}

function formatTime(dateStr?: string): string {
  if (!dateStr) return '—'
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60_000)
  const diffHours = Math.floor(diffMs / 3_600_000)
  const diffDays = Math.floor(diffMs / 86_400_000)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 30) return `${diffDays}d ago`

  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
}

function toggleExpand(feedName: string) {
  expandedFeed.value = expandedFeed.value === feedName ? null : feedName
}

let pollTimer: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  fetchFeeds()
  pollTimer = setInterval(fetchFeeds, 30_000)
})

onUnmounted(() => {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
})
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold tracking-tight">Feed Status</h1>
      <p class="text-muted-foreground">Monitor and control vulnerability data source feeds</p>
    </div>

    <div aria-live="polite">
      <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 class="mr-2 size-5 animate-spin" aria-hidden="true" />
        Loading feed status...
      </div>

      <div v-else-if="error" class="py-16 text-center">
        <p class="text-sm text-destructive" role="alert">{{ error }}</p>
      </div>

      <Card v-else-if="feeds.length === 0" class="py-16">
        <CardContent class="flex flex-col items-center text-center">
          <h2 class="text-lg font-semibold">No feed data yet</h2>
          <p class="mt-1 text-sm text-muted-foreground">
            Feed status will appear once feeds have been scheduled.
          </p>
        </CardContent>
      </Card>

      <Table v-else>
        <TableHeader>
          <TableRow>
            <TableHead class="w-8"></TableHead>
            <TableHead>Feed</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Last Success</TableHead>
            <TableHead>Failures</TableHead>
            <TableHead>Last Error</TableHead>
            <TableHead class="w-48">
              <span class="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <template v-for="feed in feeds" :key="feed.feed_name">
            <TableRow>
              <TableCell>
                <button
                  v-if="feed.recent_logs.length > 0"
                  class="p-1 text-muted-foreground hover:text-foreground"
                  :aria-label="`Toggle logs for ${feed.feed_name}`"
                  @click="toggleExpand(feed.feed_name)"
                >
                  <ChevronDown v-if="expandedFeed === feed.feed_name" class="size-4" />
                  <ChevronRight v-else class="size-4" />
                </button>
              </TableCell>
              <TableCell class="font-medium">{{ feed.feed_name }}</TableCell>
              <TableCell>
                <Badge :variant="statusBadge(feed).variant">
                  {{ statusBadge(feed).label }}
                </Badge>
              </TableCell>
              <TableCell class="text-muted-foreground">
                {{ formatTime(feed.last_success_at) }}
              </TableCell>
              <TableCell>
                <span v-if="feed.consecutive_failures > 0" class="text-destructive">
                  {{ feed.consecutive_failures }}
                </span>
                <span v-else class="text-muted-foreground">0</span>
              </TableCell>
              <TableCell class="max-w-xs truncate text-sm text-muted-foreground">
                {{ feed.last_error || '—' }}
              </TableCell>
              <TableCell>
                <div class="flex items-center gap-1">
                  <Button
                    variant="outline"
                    size="sm"
                    :disabled="actionInProgress === feed.feed_name"
                    @click="triggerFeed(feed.feed_name)"
                  >
                    <Loader2
                      v-if="actionInProgress === feed.feed_name"
                      class="mr-1 size-3 animate-spin"
                      aria-hidden="true"
                    />
                    <Play v-else class="mr-1 size-3" aria-hidden="true" />
                    Run
                  </Button>
                  <Button
                    v-if="feed.paused_at"
                    variant="outline"
                    size="sm"
                    :disabled="actionInProgress === feed.feed_name"
                    @click="resumeFeed(feed.feed_name)"
                  >
                    <RotateCcw class="mr-1 size-3" aria-hidden="true" />
                    Resume
                  </Button>
                  <Button
                    v-else
                    variant="outline"
                    size="sm"
                    :disabled="actionInProgress === feed.feed_name"
                    @click="pauseFeed(feed.feed_name)"
                  >
                    <Pause class="mr-1 size-3" aria-hidden="true" />
                    Pause
                  </Button>
                </div>
              </TableCell>
            </TableRow>

            <!-- Expanded log rows -->
            <template v-if="expandedFeed === feed.feed_name">
              <TableRow
                v-for="log in feed.recent_logs"
                :key="log.id"
                class="bg-muted/30"
              >
                <TableCell></TableCell>
                <TableCell colspan="6" class="text-sm">
                  <div class="flex items-center gap-4">
                    <Badge
                      :variant="log.status === 'success' ? 'default' : 'destructive'"
                      class="text-xs"
                    >
                      {{ log.status }}
                    </Badge>
                    <span class="text-muted-foreground">
                      {{ formatTime(log.started_at) }}
                    </span>
                    <span v-if="log.items_fetched > 0">
                      {{ log.items_fetched }} fetched, {{ log.items_upserted }} upserted
                    </span>
                    <span v-if="log.error_summary" class="text-destructive">
                      {{ log.error_summary }}
                    </span>
                  </div>
                </TableCell>
              </TableRow>
            </template>
          </template>
        </TableBody>
      </Table>
    </div>
  </div>
</template>
