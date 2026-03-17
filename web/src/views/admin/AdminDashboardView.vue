<!-- ABOUTME: Site admin dashboard with summary cards and quick links. -->
<!-- ABOUTME: Displays org count, user count, feed health, and recent delivery failures. -->

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import client from '@/lib/api/client'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Loader2, Building2, Users, Activity, AlertTriangle } from 'lucide-vue-next'
import { RouterLink } from 'vue-router'

interface DashboardData {
  orgCount: number
  orgHasMore: boolean
  userCount: number
  userHasMore: boolean
  healthyFeeds: number
  failingFeeds: number
  failedDeliveryCount: number
  failedDeliveryHasMore: boolean
}

const data = ref<DashboardData | null>(null)
const loading = ref(true)
const error = ref('')

async function fetchDashboard() {
  loading.value = true
  error.value = ''

  try {
    // Fetch summary data from multiple admin endpoints in parallel.
    const [orgsResult, usersResult, feedsResult, deliveriesResult] = await Promise.all([
      client.GET('/admin/orgs', { params: { query: { limit: 1 } } }),
      client.GET('/admin/users', { params: { query: { limit: 1 } } }),
      client.GET('/admin/feeds'),
      client.GET('/admin/deliveries', { params: { query: { status: 'failed', limit: 1 } } }),
    ])

    if (orgsResult.error || usersResult.error || feedsResult.error || deliveriesResult.error) {
      error.value = 'Failed to load dashboard data.'
      loading.value = false
      return
    }

    const feeds = feedsResult.data.items ?? []
    const healthy = feeds.filter((f) => f.consecutive_failures === 0).length
    const failing = feeds.filter((f) => f.consecutive_failures > 0).length

    data.value = {
      orgCount: (orgsResult.data.items ?? []).length,
      orgHasMore: !!orgsResult.data.next_cursor,
      userCount: (usersResult.data.items ?? []).length,
      userHasMore: !!usersResult.data.next_cursor,
      healthyFeeds: healthy,
      failingFeeds: failing,
      failedDeliveryCount: (deliveriesResult.data.items ?? []).length,
      failedDeliveryHasMore: !!deliveriesResult.data.next_cursor,
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
                {{ data.orgCount }}{{ data.orgHasMore ? '+' : '' }}
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
                {{ data.userCount }}{{ data.userHasMore ? '+' : '' }}
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
                {{ data.failedDeliveryCount }}{{ data.failedDeliveryHasMore ? '+' : '' }}
              </div>
              <p
                :class="
                  data.failedDeliveryCount > 0
                    ? 'text-xs text-destructive'
                    : 'text-xs text-muted-foreground'
                "
              >
                {{ data.failedDeliveryCount > 0 ? 'Needs attention' : 'None' }}
              </p>
            </CardContent>
          </Card>
        </RouterLink>
      </div>
    </div>
  </div>
</template>
