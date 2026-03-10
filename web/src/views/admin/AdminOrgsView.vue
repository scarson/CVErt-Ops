<!-- ABOUTME: Site admin organizations list with tier management and suspend toggle. -->
<!-- ABOUTME: Follows MembersView pattern — data table with keyset pagination. -->

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
import { Loader2 } from 'lucide-vue-next'
import { toast } from 'vue-sonner'

interface OrgEntry {
  id: string
  name: string
  tier: string
  suspended_at?: string | null
  created_at: string
}

const orgs = ref<OrgEntry[]>([])
const loading = ref(true)
const error = ref('')
const hasMore = ref(false)

const TIERS = ['free', 'pro', 'enterprise'] as const

async function fetchOrgs() {
  loading.value = true
  error.value = ''

  try {
    const resp = await orgFetch('/api/v1/admin/orgs?limit=50')
    if (!resp.ok) {
      error.value = 'Failed to load organizations.'
      loading.value = false
      return
    }

    const data = (await resp.json()) as { items: OrgEntry[]; has_more: boolean }
    orgs.value = data.items ?? []
    hasMore.value = data.has_more
  } catch {
    error.value = 'Failed to load organizations.'
  } finally {
    loading.value = false
  }
}

async function changeTier(orgId: string, tier: string) {
  try {
    const resp = await orgFetch(`/api/v1/admin/orgs/${orgId}`, {
      method: 'PATCH',
      body: JSON.stringify({ tier }),
    })
    if (resp.ok) {
      const updated: OrgEntry = await resp.json()
      orgs.value = orgs.value.map((o) => (o.id === orgId ? { ...o, tier: updated.tier } : o))
      toast.success('Tier updated')
    } else {
      toast.error('Failed to update tier')
      orgs.value = [...orgs.value]
    }
  } catch {
    toast.error('Failed to update tier')
    orgs.value = [...orgs.value]
  }
}

async function toggleSuspend(org: OrgEntry) {
  const suspend = !org.suspended_at
  try {
    const resp = await orgFetch(`/api/v1/admin/orgs/${org.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ suspend }),
    })
    if (resp.ok) {
      const updated: OrgEntry = await resp.json()
      orgs.value = orgs.value.map((o) =>
        o.id === org.id ? { ...o, suspended_at: updated.suspended_at } : o,
      )
      toast.success(suspend ? 'Organization suspended' : 'Organization unsuspended')
    } else {
      toast.error('Failed to update organization')
    }
  } catch {
    toast.error('Failed to update organization')
  }
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

onMounted(fetchOrgs)
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold tracking-tight">Organizations</h1>
      <p class="text-muted-foreground">Manage all organizations</p>
    </div>

    <div aria-live="polite">
      <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 class="mr-2 size-5 animate-spin" aria-hidden="true" />
        Loading organizations...
      </div>

      <div v-else-if="error" class="py-16 text-center">
        <p class="text-sm text-destructive" role="alert">{{ error }}</p>
      </div>

      <Table v-else>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead class="w-36">Tier</TableHead>
            <TableHead class="w-28">Status</TableHead>
            <TableHead class="w-32">Created</TableHead>
            <TableHead class="w-28">
              <span class="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="org in orgs" :key="org.id">
            <TableCell class="font-medium">{{ org.name }}</TableCell>
            <TableCell>
              <Select
                :model-value="org.tier"
                @update:model-value="(val) => changeTier(org.id, String(val))"
              >
                <SelectTrigger class="w-28" size="sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem v-for="t in TIERS" :key="t" :value="t">
                    {{ t.charAt(0).toUpperCase() + t.slice(1) }}
                  </SelectItem>
                </SelectContent>
              </Select>
            </TableCell>
            <TableCell>
              <Badge :variant="org.suspended_at ? 'destructive' : 'default'">
                {{ org.suspended_at ? 'Suspended' : 'Active' }}
              </Badge>
            </TableCell>
            <TableCell class="text-muted-foreground">{{ formatDate(org.created_at) }}</TableCell>
            <TableCell>
              <Button variant="outline" size="sm" @click="toggleSuspend(org)">
                {{ org.suspended_at ? 'Unsuspend' : 'Suspend' }}
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <div v-if="hasMore && !loading" class="flex justify-center pt-4">
        <p class="text-sm text-muted-foreground">More organizations available. Pagination coming soon.</p>
      </div>
    </div>
  </div>
</template>
