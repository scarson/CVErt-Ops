<!-- ABOUTME: Compact card displaying a single metric (CVSS, EPSS, KEV, etc.) with severity coloring. -->
<!-- ABOUTME: Accepts label, value, optional sublabel, and optional severity for color coding. -->

<script setup lang="ts">
import { computed } from 'vue'
import { Card } from '@/components/ui/card'

const props = withDefaults(
  defineProps<{
    label: string
    value?: string
    sublabel?: string
    severity?: 'critical' | 'high' | 'medium' | 'low'
  }>(),
  {
    value: undefined,
    sublabel: undefined,
    severity: undefined,
  },
)

const displayValue = computed(() => props.value ?? 'N/A')

const severityClasses = computed(() => {
  switch (props.severity) {
    case 'critical':
      return 'text-red-600 dark:text-red-400'
    case 'high':
      return 'text-orange-500 dark:text-orange-400'
    case 'medium':
      return 'text-yellow-600 dark:text-yellow-400'
    case 'low':
      return 'text-green-600 dark:text-green-400'
    default:
      return 'text-foreground'
  }
})
</script>

<template>
  <Card data-testid="score-card" class="px-4 py-3 gap-1">
    <span class="text-xs font-medium uppercase tracking-wide text-muted-foreground">
      {{ label }}
    </span>
    <span
      data-testid="score-value"
      :class="['text-2xl font-bold tabular-nums', severityClasses]"
    >
      {{ displayValue }}
    </span>
    <span
      v-if="sublabel"
      class="text-xs text-muted-foreground"
    >
      {{ sublabel }}
    </span>
  </Card>
</template>
