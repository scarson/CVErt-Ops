<!-- ABOUTME: CVE search page -- main search interface with filters and results. -->
<!-- ABOUTME: Primary landing page for authenticated users. -->

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import client from '@/lib/api/client'
import type { components } from '@/lib/api/schema'
import CveSearchFilters from '@/components/cve/CveSearchFilters.vue'
import CveResultsTable from '@/components/cve/CveResultsTable.vue'
import { Button } from '@/components/ui/button'
import { usePagination } from '@/composables/usePagination'
import { ChevronLeft, ChevronRight } from 'lucide-vue-next'

type CVEItem = components['schemas']['CVEItem']

const route = useRoute()
const router = useRouter()

const query = ref((route.query.q as string) ?? '')
const severity = ref((route.query.severity as string) ?? '')
const items = ref<CVEItem[]>([])
const loading = ref(false)
const error = ref('')

const { cursor, hasPrev, hasNext, setNextCursor, goNext, goPrev, reset } = usePagination()

const PAGE_LIMIT = 25
let fetchId = 0

async function fetchCves() {
  const currentFetchId = ++fetchId
  loading.value = true
  error.value = ''

  const params: Record<string, unknown> = {
    limit: PAGE_LIMIT,
  }
  if (query.value) params.q = query.value
  if (severity.value) params.severity = [severity.value]
  if (cursor.value) params.cursor = cursor.value

  const { data, error: apiError } = await client.GET('/cves', {
    params: {
      query: params as Record<string, never>,
    },
  })

  // Discard stale response if a newer fetch was started.
  if (currentFetchId !== fetchId) return

  loading.value = false

  if (apiError || !data) {
    error.value = 'Failed to load CVEs. Please try again.'
    items.value = []
    setNextCursor(undefined)
    return
  }

  items.value = data.items ?? []
  setNextCursor(data.next_cursor)
}

function onSearch(filters: { query: string; severity: string }) {
  query.value = filters.query
  severity.value = filters.severity
  reset()
  updateUrl()
  fetchCves()
}

function onNextPage() {
  goNext()
  fetchCves()
}

function onPrevPage() {
  goPrev()
  fetchCves()
}

function updateUrl() {
  const urlQuery: Record<string, string> = {}
  if (query.value) urlQuery.q = query.value
  if (severity.value) urlQuery.severity = severity.value
  router.replace({ query: urlQuery })
}

onMounted(() => {
  fetchCves()
})
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-semibold tracking-tight">CVE Search</h1>
      <p class="text-sm text-muted-foreground">
        Search and browse the global CVE database.
      </p>
    </div>

    <CveSearchFilters
      :query="query"
      :severity="severity"
      @search="onSearch"
    />

    <p v-if="error" class="text-sm text-destructive" role="alert">{{ error }}</p>

    <CveResultsTable :items="items" :loading="loading" />

    <div class="flex items-center justify-end gap-2">
      <Button
        data-testid="prev-page"
        variant="outline"
        size="sm"
        :disabled="!hasPrev"
        @click="onPrevPage"
      >
        <ChevronLeft class="mr-1 size-4" aria-hidden="true" />
        Previous
      </Button>
      <Button
        data-testid="next-page"
        variant="outline"
        size="sm"
        :disabled="!hasNext"
        @click="onNextPage"
      >
        Next
        <ChevronRight class="ml-1 size-4" aria-hidden="true" />
      </Button>
    </div>
  </div>
</template>
