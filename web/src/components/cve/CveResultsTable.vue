<!-- ABOUTME: Table displaying CVE search results with severity badges and EPSS scores. -->
<!-- ABOUTME: Handles loading, empty, and populated states for the results list. -->

<script setup lang="ts">
import { RouterLink } from 'vue-router'
import type { components } from '@/lib/api/schema'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Loader2 } from 'lucide-vue-next'

type CVEItem = components['schemas']['CVEItem']

defineProps<{
  items: CVEItem[]
  loading: boolean
}>()

const DESCRIPTION_MAX_LENGTH = 120

function truncate(text: string | undefined, max: number): string {
  if (!text) return ''
  if (text.length <= max) return text
  return text.slice(0, max) + '...'
}

function formatEpss(score: number | undefined): string {
  if (score == null) return '\u2014'
  return `${(score * 100).toFixed(1)}%`
}

function formatDate(dateStr: string): string {
  const date = new Date(dateStr)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

type SeverityColor = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

function severityColor(severity: string | undefined): SeverityColor {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical'
    case 'high': return 'high'
    case 'medium': return 'medium'
    case 'low': return 'low'
    default: return 'unknown'
  }
}

function cvssDisplay(item: CVEItem): string {
  const score = item.cvss_v3_score ?? item.cvss_v4_score
  if (score == null) return 'N/A'
  return score.toFixed(1)
}
</script>

<template>
  <div aria-live="polite">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead class="w-40">CVE ID</TableHead>
          <TableHead>Description</TableHead>
          <TableHead class="w-24 text-center">CVSS</TableHead>
          <TableHead class="w-20 text-center">EPSS</TableHead>
          <TableHead class="w-32 text-right">Modified</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-if="loading">
          <TableCell :colspan="5" class="h-32 text-center">
            <div class="flex items-center justify-center gap-2 text-muted-foreground">
              <Loader2 class="size-4 animate-spin" aria-hidden="true" />
              Loading...
            </div>
          </TableCell>
        </TableRow>

        <TableRow v-else-if="items.length === 0">
          <TableCell :colspan="5" class="h-32 text-center text-muted-foreground">
            No CVEs found matching your search
          </TableCell>
        </TableRow>

        <TableRow v-for="item in items" v-else :key="item.cve_id">
          <TableCell class="font-mono text-sm">
            <RouterLink
              :to="`/cves/${item.cve_id}`"
              class="font-medium text-foreground underline-offset-4 hover:underline"
            >
              {{ item.cve_id }}
            </RouterLink>
          </TableCell>

          <TableCell class="max-w-md text-sm text-muted-foreground">
            {{ truncate(item.description_primary, DESCRIPTION_MAX_LENGTH) }}
          </TableCell>

          <TableCell class="text-center">
            <Badge
              data-testid="cvss-badge"
              :class="[
                'text-xs font-semibold',
                {
                  'bg-red-600 text-white border-red-600': severityColor(item.severity) === 'critical',
                  'bg-orange-500 text-white border-orange-500': severityColor(item.severity) === 'high',
                  'bg-yellow-600 text-white border-yellow-600': severityColor(item.severity) === 'medium',
                  'bg-green-600 text-white border-green-600': severityColor(item.severity) === 'low',
                  'bg-muted text-muted-foreground border-muted': severityColor(item.severity) === 'unknown',
                },
              ]"
            >
              {{ cvssDisplay(item) }}
            </Badge>
          </TableCell>

          <TableCell class="text-center text-sm tabular-nums">
            {{ formatEpss(item.epss_score) }}
          </TableCell>

          <TableCell class="text-right text-sm tabular-nums text-muted-foreground">
            {{ formatDate(item.date_modified) }}
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </div>
</template>
