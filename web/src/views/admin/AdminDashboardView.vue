<!-- ABOUTME: Site admin dashboard with summary cards and quick links. -->
<!-- ABOUTME: Displays org count, user count, feed health, and recent delivery failures. -->

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { orgFetch } from '@/lib/api/orgFetch'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Loader2, Building2, Users, Activity, AlertTriangle } from 'lucide-vue-next'
import { RouterLink } from 'vue-router'

interface DashboardData {
  orgCount: number
  userCount: number
  healthyFeeds: number
  failingFeeds: number
  recentFailedDeliveries: number
}

const data = ref<DashboardData | null>(null)
const loading = ref(true)
const error = ref('')

async function fetchDashboard() {
  loading.value = true
  error.value = ''

  try {
    // Fetch summary data from multiple admin endpoints in parallel.
    const [orgsResp, usersResp, feedsResp, deliveriesResp] = await Promise.all([
      orgFetch('/api/v1/admin/orgs?limit=1'),
      orgFetch('/api/v1/admin/users?limit=1'),
      orgFetch('/api/v1/admin/feeds'),
      orgFetch('/api/v1/admin/deliveries?status=failed&limit=1'),
    ])

    if (!orgsResp.ok || !usersResp.ok || !feedsResp.ok || !deliveriesResp.ok) {
      error.value = 'Failed to load dashboard data.'
      loading.value = false
      return
    }

    const orgsData = (await orgsResp.json()) as { items: unknown[]; has_more: boolean }
    const usersData = (await usersResp.json()) as { items: unknown[]; has_more: boolean }
    const feedsData = (await feedsResp.json()) as {
      feeds: { consecutive_failures: number }[]
    }
    const deliveriesData = (await deliveriesResp.json()) as {
      items: unknown[]
      has_more: boolean
    }

    const feeds = feedsData.feeds ?? []
    const healthy = feeds.filter((f) => f.consecutive_failures === 0).length
    const failing = feeds.filter((f) => f.consecutive_failures > 0).length

    data.value = {
      // These are approximations — the list endpoints return paginated data,
      // so we can't get exact counts. Show "1+" if has_more.
      orgCount: orgsData.items.length + (orgsData.has_more ? 1 : 0),
      userCount: usersData.items.length + (usersData.has_more ? 1 : 0),
      healthyFeeds: healthy,
      failingFeeds: failing,
      recentFailedDeliveries: deliveriesData.items.length + (deliveriesData.has_more ? 1 : 0),
    }
  } catch {
    error.value = 'Failed to load dashboard data.'
  } finally {
    loading.value = false
  }
}

onMounted(fetchDashboard)
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold tracking-tight">Admin Dashboard</h1>
      <p class="text-muted-foreground">System overview and quick links</p>
    </div>

    <div aria-live="polite">
      <!-- Loading state -->
      <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 class="mr-2 size-5 animate-spin" aria-hidden="true" />
        Loading dashboard...
      </div>

      <!-- Error state -->
      <div v-else-if="error" class="py-16 text-center">
        <p class="text-sm text-destructive" role="alert">{{ error }}</p>
      </div>

      <!-- Dashboard cards -->
      <div v-else-if="data" class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <RouterLink to="/admin/orgs" class="block">
          <Card class="transition-colors hover:bg-muted/50">
            <CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle class="text-sm font-medium">Organizations</CardTitle>
              <Building2 class="size-4 text-muted-foreground" aria-hidden="true" />
            </CardHeader>
            <CardContent>
              <div class="text-2xl font-bold">
                {{ data.orgCount }}{{ data.orgCount > 1 ? '+' : '' }}
              </div>
            </CardContent>
          </Card>
        </RouterLink>

        <RouterLink to="/admin/users" class="block">
          <Card class="transition-colors hover:bg-muted/50">
            <CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle class="text-sm font-medium">Users</CardTitle>
              <Users class="size-4 text-muted-foreground" aria-hidden="true" />
            </CardHeader>
            <CardContent>
              <div class="text-2xl font-bold">
                {{ data.userCount }}{{ data.userCount > 1 ? '+' : '' }}
              </div>
            </CardContent>
          </Card>
        </RouterLink>

        <RouterLink to="/admin/feeds" class="block">
          <Card class="transition-colors hover:bg-muted/50">
            <CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle class="text-sm font-medium">Feed Health</CardTitle>
              <Activity class="size-4 text-muted-foreground" aria-hidden="true" />
            </CardHeader>
            <CardContent>
              <div class="text-2xl font-bold">
                {{ data.healthyFeeds }} / {{ data.healthyFeeds + data.failingFeeds }}
              </div>
              <p v-if="data.failingFeeds > 0" class="text-xs text-destructive">
                {{ data.failingFeeds }} failing
              </p>
              <p v-else class="text-xs text-muted-foreground">All healthy</p>
            </CardContent>
          </Card>
        </RouterLink>

        <RouterLink to="/admin/deliveries" class="block">
          <Card class="transition-colors hover:bg-muted/50">
            <CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle class="text-sm font-medium">Failed Deliveries</CardTitle>
              <AlertTriangle class="size-4 text-muted-foreground" aria-hidden="true" />
            </CardHeader>
            <CardContent>
              <div class="text-2xl font-bold">
                {{ data.recentFailedDeliveries > 0 ? data.recentFailedDeliveries + '+' : '0' }}
              </div>
              <p
                :class="
                  data.recentFailedDeliveries > 0
                    ? 'text-xs text-destructive'
                    : 'text-xs text-muted-foreground'
                "
              >
                {{ data.recentFailedDeliveries > 0 ? 'Needs attention' : 'None' }}
              </p>
            </CardContent>
          </Card>
        </RouterLink>
      </div>
    </div>
  </div>
</template>
