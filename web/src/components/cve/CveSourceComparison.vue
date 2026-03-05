<!-- ABOUTME: Tabbed view showing per-source normalized data for cross-source comparison. -->
<!-- ABOUTME: Each tab displays one feed source's metadata and normalized JSON payload. -->

<script setup lang="ts">
import { computed } from 'vue'
import type { components } from '@/lib/api/schema'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Loader2 } from 'lucide-vue-next'

type CVESourceResponse = components['schemas']['CVESourceResponse']

const props = defineProps<{
  sources: CVESourceResponse[]
  loading: boolean
}>()

const KNOWN_UPPERCASE = new Set(['nvd', 'mitre', 'ghsa', 'osv', 'kev', 'epss'])

function formatSourceName(name: string): string {
  if (KNOWN_UPPERCASE.has(name.toLowerCase())) {
    return name.toUpperCase()
  }
  return name.charAt(0).toUpperCase() + name.slice(1)
}

function formatDate(dateStr: string | undefined): string {
  if (!dateStr) return '\u2014'
  const date = new Date(dateStr)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function extractHostname(url: string | undefined): string {
  if (!url) return ''
  try {
    return new URL(url).hostname
  } catch {
    return url
  }
}

function formatJson(data: unknown): string {
  if (data == null) return '{}'
  return JSON.stringify(data, null, 2)
}

const defaultTab = computed(() =>
  props.sources.length > 0 ? props.sources[0]!.source_name : '',
)
</script>

<template>
  <div>
    <div v-if="loading" class="flex items-center justify-center py-8 text-muted-foreground">
      <Loader2 class="mr-2 size-4 animate-spin" />
      Loading sources...
    </div>

    <div
      v-else-if="sources.length === 0"
      class="py-8 text-center text-sm text-muted-foreground"
    >
      No source data available
    </div>

    <Tabs v-else :default-value="defaultTab">
      <TabsList>
        <TabsTrigger
          v-for="source in sources"
          :key="source.source_name"
          :value="source.source_name"
        >
          {{ formatSourceName(source.source_name) }}
        </TabsTrigger>
      </TabsList>

      <TabsContent
        v-for="source in sources"
        :key="source.source_name"
        :value="source.source_name"
        class="mt-4 space-y-4"
      >
        <div class="flex flex-wrap gap-x-6 gap-y-1 text-sm text-muted-foreground">
          <span v-if="source.source_url">
            Source:
            <a
              :href="source.source_url"
              target="_blank"
              rel="noopener noreferrer"
              class="underline underline-offset-4 hover:text-foreground"
            >
              {{ extractHostname(source.source_url) }}
            </a>
          </span>
          <span v-if="source.source_date_modified">
            Modified: {{ formatDate(source.source_date_modified) }}
          </span>
          <span>
            Ingested: {{ formatDate(source.ingested_at) }}
          </span>
        </div>

        <pre class="overflow-auto rounded-md border bg-muted/50 p-4 text-xs leading-relaxed">{{ formatJson(source.normalized_json) }}</pre>
      </TabsContent>
    </Tabs>
  </div>
</template>
