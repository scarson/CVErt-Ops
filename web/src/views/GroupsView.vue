<!-- ABOUTME: Organization groups page — manage member groups. -->
<!-- ABOUTME: Admin+ can create/edit/delete groups and manage membership. -->

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import GroupDialog from '@/components/settings/GroupDialog.vue'
import type { GroupEntry } from '@/components/settings/GroupDialog.vue'
import GroupMembersDialog from '@/components/settings/GroupMembersDialog.vue'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Plus, Trash2, Pencil, Users, Loader2 } from 'lucide-vue-next'

const ROLE_HIERARCHY: Record<string, number> = {
  owner: 4,
  admin: 3,
  member: 2,
  viewer: 1,
}

const auth = useAuthStore()

const groups = ref<GroupEntry[]>([])
const loading = ref(true)
const error = ref('')

const groupDialogOpen = ref(false)
const editTarget = ref<GroupEntry | null>(null)
const deleteTarget = ref<GroupEntry | null>(null)
const deleteDialogOpen = ref(false)
const membersDialogOpen = ref(false)
const membersTarget = ref<GroupEntry | null>(null)

const userRole = computed(() => auth.activeOrg?.role ?? 'viewer')
const isAdmin = computed(() => ROLE_HIERARCHY[userRole.value]! >= ROLE_HIERARCHY['admin']!)

function apiBase() {
  return `/api/v1/orgs/${auth.activeOrgId}/groups`
}

async function fetchGroups() {
  loading.value = true
  error.value = ''

  try {
    const resp = await fetch(apiBase(), {
      method: 'GET',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    })

    if (!resp.ok) {
      error.value = 'Failed to load groups. Please try again.'
      loading.value = false
      return
    }

    groups.value = await resp.json() as GroupEntry[]
  } catch {
    error.value = 'Failed to load groups. Please try again.'
  } finally {
    loading.value = false
  }
}

function openCreateDialog() {
  editTarget.value = null
  groupDialogOpen.value = true
}

function openEditDialog(group: GroupEntry) {
  editTarget.value = group
  groupDialogOpen.value = true
}

function onGroupSaved(entry: GroupEntry) {
  if (editTarget.value) {
    groups.value = groups.value.map((g) =>
      g.id === entry.id ? entry : g,
    )
  } else {
    groups.value = [...groups.value, entry]
  }
}

function promptDelete(group: GroupEntry) {
  deleteTarget.value = group
  deleteDialogOpen.value = true
}

async function confirmDelete() {
  if (!deleteTarget.value) return

  const id = deleteTarget.value.id

  try {
    const resp = await fetch(`${apiBase()}/${id}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-By': 'CVErt-Ops',
      },
    })

    if (resp.ok) {
      groups.value = groups.value.filter((g) => g.id !== id)
    }
  } finally {
    deleteDialogOpen.value = false
    deleteTarget.value = null
  }
}

function openMembersDialog(group: GroupEntry) {
  membersTarget.value = group
  membersDialogOpen.value = true
}

function formatDate(dateStr: string): string {
  const date = new Date(dateStr)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

onMounted(() => {
  fetchGroups()
})

watch(
  () => auth.activeOrgId,
  () => {
    fetchGroups()
  },
)
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">Groups</h1>
        <p class="text-sm text-muted-foreground">
          Organize members into groups for watchlist sharing
        </p>
      </div>
      <Button
        v-if="isAdmin"
        data-testid="new-group-btn"
        @click="openCreateDialog"
      >
        <Plus class="mr-2 size-4" />
        New Group
      </Button>
    </div>

    <!-- Loading state -->
    <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
      <Loader2 class="mr-2 size-5 animate-spin" />
      Loading groups...
    </div>

    <!-- Error state -->
    <div v-else-if="error" class="py-16 text-center">
      <p class="text-sm text-destructive">{{ error }}</p>
    </div>

    <!-- Empty state -->
    <Card v-else-if="groups.length === 0" class="py-16">
      <CardContent class="flex flex-col items-center text-center">
        <Users class="mb-4 size-12 text-muted-foreground" />
        <h2 class="text-lg font-semibold">No groups yet</h2>
        <p class="mt-1 text-sm text-muted-foreground">
          Create your first group to organize members
        </p>
        <Button
          v-if="isAdmin"
          class="mt-4"
          data-testid="empty-create-group-btn"
          @click="openCreateDialog"
        >
          <Plus class="mr-2 size-4" />
          New Group
        </Button>
      </CardContent>
    </Card>

    <!-- Groups table -->
    <Table v-else>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Description</TableHead>
          <TableHead class="w-36">Created</TableHead>
          <TableHead v-if="isAdmin" class="w-32" />
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="g in groups" :key="g.id">
          <TableCell class="font-medium">{{ g.name }}</TableCell>
          <TableCell class="text-muted-foreground">{{ g.description }}</TableCell>
          <TableCell class="text-muted-foreground">
            {{ formatDate(g.created_at) }}
          </TableCell>
          <TableCell v-if="isAdmin">
            <div class="flex items-center gap-1">
              <Button
                variant="ghost"
                size="sm"
                data-testid="edit-group-btn"
                @click="openEditDialog(g)"
              >
                <Pencil class="size-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                data-testid="manage-members-btn"
                @click="openMembersDialog(g)"
              >
                <Users class="size-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                data-testid="delete-group-btn"
                @click="promptDelete(g)"
              >
                <Trash2 class="size-4 text-destructive" />
              </Button>
            </div>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>

    <!-- Create/Edit group dialog -->
    <GroupDialog
      :open="groupDialogOpen"
      :group="editTarget"
      @update:open="groupDialogOpen = $event"
      @saved="onGroupSaved"
    />

    <!-- Members dialog -->
    <GroupMembersDialog
      v-if="membersTarget"
      :open="membersDialogOpen"
      :group-id="membersTarget.id"
      :group-name="membersTarget.name"
      @update:open="membersDialogOpen = $event"
    />

    <!-- Delete confirmation dialog -->
    <AlertDialog :open="deleteDialogOpen" @update:open="deleteDialogOpen = $event">
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Are you sure?</AlertDialogTitle>
          <AlertDialogDescription>
            This will permanently delete the group. Members will not be removed from the organization.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel @click="deleteDialogOpen = false">Cancel</AlertDialogCancel>
          <AlertDialogAction
            data-testid="confirm-delete-group-btn"
            class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            @click="confirmDelete"
          >
            Delete
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  </div>
</template>
