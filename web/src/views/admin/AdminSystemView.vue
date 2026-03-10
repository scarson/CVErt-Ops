<!-- ABOUTME: Site admin system page — read-only cards for config, doctor results, and version info. -->
<!-- ABOUTME: Fetches from /version, /doctor, and /admin/config endpoints. -->

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { orgFetch } from '@/lib/api/orgFetch'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Loader2, RefreshCcw } from 'lucide-vue-next'

interface VersionInfo {
  version: string
  commit: string
  build_time: string
  go_version: string
}

interface DoctorCheck {
  name: string
  status: string
  message: string
  duration_ms: number
}

interface DoctorResult {
  status: string
  checks: DoctorCheck[]
}

const version = ref<VersionInfo | null>(null)
const doctor = ref<DoctorResult | null>(null)
const config = ref<Record<string, unknown> | null>(null)
const loading = ref(true)
const error = ref('')
const runningDoctor = ref(false)

async function fetchAll() {
  loading.value = true
  error.value = ''

  try {
    const [versionResp, doctorResp, configResp] = await Promise.all([
      orgFetch('/api/v1/version'),
      orgFetch('/api/v1/doctor'),
      orgFetch('/api/v1/admin/config'),
    ])

    if (versionResp.ok) {
      version.value = (await versionResp.json()) as VersionInfo
    }
    if (doctorResp.ok) {
      doctor.value = (await doctorResp.json()) as DoctorResult
    }
    if (configResp.ok) {
      config.value = (await configResp.json()) as Record<string, unknown>
    }

    if (!versionResp.ok && !doctorResp.ok && !configResp.ok) {
      error.value = 'Failed to load system information.'
    }
  } catch {
    error.value = 'Failed to load system information.'
  } finally {
    loading.value = false
  }
}

async function runDoctor() {
  runningDoctor.value = true
  try {
    const resp = await orgFetch('/api/v1/doctor')
    if (resp.ok) {
      doctor.value = (await resp.json()) as DoctorResult
    }
  } catch {
    // Silently fail — the existing data stays.
  } finally {
    runningDoctor.value = false
  }
}

function checkBadgeVariant(status: string): 'default' | 'destructive' | 'secondary' {
  if (status === 'pass' || status === 'ok') return 'default'
  if (status === 'fail' || status === 'error') return 'destructive'
  return 'secondary'
}

onMounted(fetchAll)
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold tracking-tight">System</h1>
      <p class="text-muted-foreground">Version, health checks, and runtime configuration</p>
    </div>

    <div aria-live="polite">
      <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 class="mr-2 size-5 animate-spin" aria-hidden="true" />
        Loading system info...
      </div>

      <div v-else-if="error" class="py-16 text-center">
        <p class="text-sm text-destructive" role="alert">{{ error }}</p>
      </div>

      <div v-else class="space-y-6">
        <!-- Version Card -->
        <Card v-if="version">
          <CardHeader>
            <CardTitle>Version</CardTitle>
          </CardHeader>
          <CardContent>
            <dl class="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
              <div>
                <dt class="text-muted-foreground">Version</dt>
                <dd class="font-medium">{{ version.version || 'dev' }}</dd>
              </div>
              <div>
                <dt class="text-muted-foreground">Commit</dt>
                <dd class="font-mono text-xs">{{ version.commit || 'unknown' }}</dd>
              </div>
              <div>
                <dt class="text-muted-foreground">Build Time</dt>
                <dd>{{ version.build_time || 'unknown' }}</dd>
              </div>
              <div>
                <dt class="text-muted-foreground">Go Version</dt>
                <dd>{{ version.go_version || 'unknown' }}</dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        <!-- Doctor Card -->
        <Card v-if="doctor">
          <CardHeader class="flex flex-row items-center justify-between space-y-0">
            <CardTitle>Health Checks</CardTitle>
            <Button variant="outline" size="sm" :disabled="runningDoctor" @click="runDoctor">
              <Loader2
                v-if="runningDoctor"
                class="mr-1 size-3 animate-spin"
                aria-hidden="true"
              />
              <RefreshCcw v-else class="mr-1 size-3" aria-hidden="true" />
              Run
            </Button>
          </CardHeader>
          <CardContent>
            <div class="mb-3">
              <Badge :variant="checkBadgeVariant(doctor.status)">
                {{ doctor.status }}
              </Badge>
            </div>
            <div class="space-y-2">
              <div
                v-for="check in doctor.checks"
                :key="check.name"
                class="flex items-center justify-between rounded-md border px-3 py-2 text-sm"
              >
                <div class="flex items-center gap-2">
                  <Badge :variant="checkBadgeVariant(check.status)" class="text-xs">
                    {{ check.status }}
                  </Badge>
                  <span class="font-medium">{{ check.name }}</span>
                </div>
                <div class="flex items-center gap-3 text-muted-foreground">
                  <span>{{ check.message }}</span>
                  <span class="text-xs">{{ check.duration_ms }}ms</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <!-- Config Card -->
        <Card v-if="config">
          <CardHeader>
            <CardTitle>Runtime Configuration</CardTitle>
          </CardHeader>
          <CardContent>
            <div class="max-h-96 overflow-auto rounded-md bg-muted p-4">
              <pre class="text-xs">{{ JSON.stringify(config, null, 2) }}</pre>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  </div>
</template>
