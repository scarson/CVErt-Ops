<!-- ABOUTME: CVE detail page — full vulnerability information with sources. -->
<!-- ABOUTME: Shows CVSS, EPSS, references, affected products, and source data. -->

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import { RouterLink } from 'vue-router'
import client from '@/lib/api/client'
import type { components } from '@/lib/api/schema'
import { safeHref } from '@/lib/utils'
import CveScoreCard from '@/components/cve/CveScoreCard.vue'
import CveSourceComparison from '@/components/cve/CveSourceComparison.vue'
import { Badge } from '@/components/ui/badge'
import { Loader2, ArrowLeft, ExternalLink } from 'lucide-vue-next'

type CVEDetail = components['schemas']['CVEDetail']
type CVESourceResponse = components['schemas']['CVESourceResponse']
type SeverityLevel = 'critical' | 'high' | 'medium' | 'low'

const route = useRoute()
const cveId = computed(() => route.params.cveId as string)

const cve = ref<CVEDetail | null>(null)
const sources = ref<CVESourceResponse[]>([])
const loading = ref(true)
const sourcesLoading = ref(true)
const notFound = ref(false)
const error = ref('')

function formatDate(dateStr: string | undefined): string {
  if (!dateStr) return '\u2014'
  const date = new Date(dateStr)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function cvssDisplay(detail: CVEDetail): string | undefined {
  const score = detail.cvss_v3_score ?? detail.cvss_v4_score
  if (score == null) return undefined
  return score.toFixed(1)
}

function epssDisplay(detail: CVEDetail): string | undefined {
  if (detail.epss_score == null) return undefined
  return `${(detail.epss_score * 100).toFixed(1)}%`
}

function severityLevel(severity: string | undefined): SeverityLevel | undefined {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical'
    case 'high': return 'high'
    case 'medium': return 'medium'
    case 'low': return 'low'
    default: return undefined
  }
}

function cvssVector(detail: CVEDetail): string | undefined {
  return detail.cvss_v3_vector ?? detail.cvss_v4_vector
}

const hasAffectedProducts = computed(() => {
  if (!cve.value) return false
  const pkgs = cve.value.affected_packages
  const cpes = cve.value.affected_cpes
  return (pkgs && pkgs.length > 0) || (cpes && cpes.length > 0)
})

const hasReferences = computed(() => {
  if (!cve.value) return false
  return cve.value.references && cve.value.references.length > 0
})

async function fetchCve() {
  loading.value = true
  error.value = ''
  notFound.value = false

  const { data, error: apiError } = await client.GET('/cves/{cve_id}', {
    params: { path: { cve_id: cveId.value } },
  })

  if (apiError || !data) {
    loading.value = false
    if (apiError && 'status' in apiError && apiError.status === 404) {
      notFound.value = true
    } else {
      error.value = 'Failed to load CVE details. Please try again.'
    }
    return
  }

  cve.value = data
  loading.value = false
}

async function fetchSources() {
  sourcesLoading.value = true

  const { data } = await client.GET('/cves/{cve_id}/sources', {
    params: { path: { cve_id: cveId.value } },
  })

  sources.value = data?.sources ?? []
  sourcesLoading.value = false
}

onMounted(() => {
  fetchCve()
  fetchSources()
})

watch(cveId, () => {
  fetchCve()
  fetchSources()
})
</script>

<template>
  <div class="space-y-8">
    <!-- Back link -->
    <RouterLink
      to="/cves"
      data-testid="back-link"
      class="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft class="size-4" />
      Back to search
    </RouterLink>

    <!-- Loading state -->
    <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
      <Loader2 class="mr-2 size-5 animate-spin" />
      Loading CVE details...
    </div>

    <!-- 404 state -->
    <div v-else-if="notFound" class="py-16 text-center">
      <h2 class="text-xl font-semibold">CVE not found</h2>
      <p class="mt-2 text-sm text-muted-foreground">
        The CVE identifier "{{ cveId }}" was not found in the database.
      </p>
    </div>

    <!-- Error state -->
    <div v-else-if="error" class="py-16 text-center">
      <p class="text-sm text-destructive" role="alert">{{ error }}</p>
    </div>

    <!-- CVE detail content -->
    <template v-else-if="cve">
      <!-- Header -->
      <div class="space-y-2">
        <div class="flex items-center gap-3">
          <h1 class="text-2xl font-semibold tracking-tight font-mono">
            {{ cve.cve_id }}
          </h1>
          <Badge
            v-if="cve.status"
            variant="outline"
            class="text-xs"
          >
            {{ cve.status }}
          </Badge>
        </div>
        <div class="flex gap-4 text-sm text-muted-foreground">
          <span v-if="cve.date_published">Published: {{ formatDate(cve.date_published) }}</span>
          <span>Modified: {{ formatDate(cve.date_modified) }}</span>
        </div>
      </div>

      <!-- Score cards -->
      <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <CveScoreCard
          label="CVSS"
          :value="cvssDisplay(cve)"
          :severity="severityLevel(cve.severity)"
          :sublabel="cve.severity ? cve.severity.charAt(0).toUpperCase() + cve.severity.slice(1) : undefined"
        />
        <CveScoreCard
          label="EPSS"
          :value="epssDisplay(cve)"
        />
        <CveScoreCard
          label="KEV"
          :value="cve.in_cisa_kev ? 'Yes' : 'No'"
          :severity="cve.in_cisa_kev ? 'critical' : undefined"
        />
        <CveScoreCard
          label="Exploit"
          :value="cve.exploit_available ? 'Yes' : 'No'"
          :severity="cve.exploit_available ? 'high' : undefined"
        />
      </div>

      <!-- CVSS vector -->
      <div v-if="cvssVector(cve)" class="text-xs font-mono text-muted-foreground">
        {{ cvssVector(cve) }}
      </div>

      <!-- Description -->
      <section class="space-y-2">
        <h2 class="text-lg font-semibold">Description</h2>
        <p v-if="cve.description_primary" class="text-sm leading-relaxed">
          {{ cve.description_primary }}
        </p>
        <p v-else class="text-sm text-muted-foreground italic">
          No description available
        </p>
      </section>

      <!-- CWE IDs -->
      <section v-if="cve.cwe_ids && cve.cwe_ids.length > 0" class="space-y-2">
        <h2 class="text-lg font-semibold">Weaknesses</h2>
        <div class="flex flex-wrap gap-2">
          <Badge
            v-for="cweId in cve.cwe_ids"
            :key="cweId"
            variant="secondary"
            class="font-mono text-xs"
          >
            {{ cweId }}
          </Badge>
        </div>
      </section>

      <!-- Affected products -->
      <section class="space-y-2">
        <h2 class="text-lg font-semibold">Affected Products</h2>

        <div v-if="!hasAffectedProducts" class="text-sm text-muted-foreground italic">
          No affected products listed
        </div>

        <!-- Packages -->
        <div v-if="cve.affected_packages && cve.affected_packages.length > 0" class="space-y-2">
          <div
            v-for="(pkg, idx) in cve.affected_packages"
            :key="idx"
            class="rounded-md border px-4 py-3 text-sm"
          >
            <div class="font-mono font-medium">{{ pkg.package_name }}</div>
            <div class="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span>Ecosystem: {{ pkg.ecosystem }}</span>
              <span v-if="pkg.introduced">Introduced: {{ pkg.introduced }}</span>
              <span v-if="pkg.fixed">Fixed: {{ pkg.fixed }}</span>
              <span v-if="pkg.namespace">Namespace: {{ pkg.namespace }}</span>
            </div>
          </div>
        </div>

        <!-- CPEs -->
        <div v-if="cve.affected_cpes && cve.affected_cpes.length > 0" class="space-y-2">
          <div
            v-for="(cpeEntry, idx) in cve.affected_cpes"
            :key="idx"
            class="rounded-md border px-4 py-3 text-sm"
          >
            <div class="font-medium">{{ cpeEntry.cpe_normalized }}</div>
            <div class="mt-1 font-mono text-xs text-muted-foreground">{{ cpeEntry.cpe }}</div>
          </div>
        </div>
      </section>

      <!-- References -->
      <section class="space-y-2">
        <h2 class="text-lg font-semibold">References</h2>

        <div v-if="!hasReferences" class="text-sm text-muted-foreground italic">
          No references listed
        </div>

        <ul v-else class="space-y-2">
          <li
            v-for="(ref, idx) in cve.references"
            :key="idx"
            class="flex items-start gap-2 text-sm"
          >
            <ExternalLink class="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
            <div>
              <a
                :href="safeHref(ref.url)"
                target="_blank"
                rel="noopener noreferrer"
                class="break-all underline underline-offset-4 hover:text-foreground"
              >
                {{ ref.url }}
              </a>
              <div v-if="ref.tags && ref.tags.length > 0" class="mt-1 flex flex-wrap gap-1">
                <Badge
                  v-for="tag in ref.tags"
                  :key="tag"
                  variant="secondary"
                  class="text-xs"
                >
                  {{ tag }}
                </Badge>
              </div>
            </div>
          </li>
        </ul>
      </section>

      <!-- Source comparison -->
      <section class="space-y-2">
        <h2 class="text-lg font-semibold">Sources</h2>
        <CveSourceComparison :sources="sources" :loading="sourcesLoading" />
      </section>
    </template>
  </div>
</template>
