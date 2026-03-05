<!-- ABOUTME: Feed status page placeholder for when feed adapters are not yet configured. -->
<!-- ABOUTME: Shows a message indicating feed monitoring is coming soon. -->

<script setup lang="ts">
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-2xl font-bold tracking-tight">Feed Status</h1>
      <p class="text-muted-foreground">Monitor vulnerability data source health</p>
    </div>

    <Card>
      <CardHeader>
        <div class="flex items-center gap-2">
          <CardTitle>Data Sources</CardTitle>
          <Badge variant="secondary">Coming soon</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <p class="text-muted-foreground">
          Feed monitoring will be available once feed adapters are configured.
        </p>
      </CardContent>
    </Card>
  </div>
</template>
