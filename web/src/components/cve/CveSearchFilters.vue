<!-- ABOUTME: Search input and severity filter for the CVE search page. -->
<!-- ABOUTME: Emits a 'search' event with { query, severity } when the user submits. -->

<script setup lang="ts">
import { ref, watch } from 'vue'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Search } from 'lucide-vue-next'

const props = defineProps<{
  query: string
  severity: string
}>()

const emit = defineEmits<{
  search: [filters: { query: string; severity: string }]
}>()

const localQuery = ref(props.query)
const localSeverity = ref(props.severity)

watch(() => props.query, (val) => { localQuery.value = val })
watch(() => props.severity, (val) => { localSeverity.value = val })

function onSubmit() {
  emit('search', {
    query: localQuery.value,
    severity: localSeverity.value,
  })
}
</script>

<template>
  <form class="flex items-end gap-3" @submit.prevent="onSubmit">
    <div class="flex-1">
      <label for="cve-search" class="sr-only">Search CVEs</label>
      <div class="relative">
        <Search class="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          id="cve-search"
          v-model="localQuery"
          type="search"
          placeholder="Search CVEs (e.g. log4j, apache, CWE-79)..."
          class="pl-9"
        />
      </div>
    </div>

    <div>
      <label for="severity-filter" class="text-sm font-medium text-muted-foreground">Severity</label>
      <select
        id="severity-filter"
        v-model="localSeverity"
        class="flex h-9 w-36 items-center rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      >
        <option value="">All</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="unknown">Unknown</option>
      </select>
    </div>

    <Button type="submit" size="default">
      <Search class="mr-2 size-4" />
      Search
    </Button>
  </form>
</template>
