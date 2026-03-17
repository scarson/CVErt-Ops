<!-- ABOUTME: Dialog for managing group membership — add and remove org members from a group. -->
<!-- ABOUTME: Fetches group members and org members on open; exposes addMember for test access. -->

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import client from '@/lib/api/client'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Trash2, Loader2 } from 'lucide-vue-next'

interface GroupMemberEntry {
  user_id: string
  email: string
  display_name: string
  joined_at: string
}

interface OrgMemberEntry {
  user_id: string
  email: string
  display_name: string
  role: string
  joined_at: string
}

const props = defineProps<{
  open: boolean
  groupId: string
  groupName: string
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
}>()

const auth = useAuthStore()
const groupMembers = ref<GroupMemberEntry[]>([])
const orgMembers = ref<OrgMemberEntry[]>([])
const loading = ref(true)
const selectedUserId = ref('')
const actionError = ref('')
const fetchError = ref('')

const availableMembers = computed(() => {
  const memberIds = new Set(groupMembers.value.map((m) => m.user_id))
  return orgMembers.value.filter((m) => !memberIds.has(m.user_id))
})

async function fetchData() {
  loading.value = true
  fetchError.value = ''

  try {
    const [groupResult, orgResult] = await Promise.all([
      client.GET('/orgs/{org_id}/groups/{group_id}/members', {
        params: { path: { org_id: auth.activeOrgId!, group_id: props.groupId } },
      }),
      client.GET('/orgs/{org_id}/members', {
        params: { path: { org_id: auth.activeOrgId! } },
      }),
    ])

    if (groupResult.error || orgResult.error) {
      fetchError.value = 'Failed to load group members. Please try again.'
    } else {
      groupMembers.value = groupResult.data.items ?? []
      orgMembers.value = orgResult.data.items ?? []
    }
  } catch {
    fetchError.value = 'Failed to load group members. Please try again.'
  } finally {
    loading.value = false
  }
}

async function addMember(userId: string) {
  if (!userId) return

  actionError.value = ''

  try {
    const { error: fetchErr } = await client.POST('/orgs/{org_id}/groups/{group_id}/members', {
      params: { path: { org_id: auth.activeOrgId!, group_id: props.groupId } },
      body: { user_id: userId },
    })

    if (!fetchErr) {
      // Move the user from available to group members
      const orgMember = orgMembers.value.find((m) => m.user_id === userId)
      if (orgMember) {
        groupMembers.value = [
          ...groupMembers.value,
          {
            user_id: orgMember.user_id,
            email: orgMember.email,
            display_name: orgMember.display_name,
            joined_at: new Date().toISOString(),
          },
        ]
      }
      selectedUserId.value = ''
    } else {
      actionError.value = 'Failed to add member. Please try again.'
    }
  } catch {
    actionError.value = 'Failed to add member. Please try again.'
  }
}

async function removeMember(userId: string) {
  actionError.value = ''

  try {
    const { error: fetchErr } = await client.DELETE('/orgs/{org_id}/groups/{group_id}/members/{user_id}', {
      params: { path: { org_id: auth.activeOrgId!, group_id: props.groupId, user_id: userId } },
    })

    if (!fetchErr) {
      groupMembers.value = groupMembers.value.filter((m) => m.user_id !== userId)
    } else {
      actionError.value = 'Failed to remove member. Please try again.'
    }
  } catch {
    actionError.value = 'Failed to remove member. Please try again.'
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function handleSelectAdd(userId: string | number | bigint | Record<string, any> | null) {
  if (typeof userId === 'string') {
    addMember(userId)
  }
}

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      groupMembers.value = []
      orgMembers.value = []
      selectedUserId.value = ''
      actionError.value = ''
      fetchError.value = ''
      fetchData()
    }
  },
  { immediate: true },
)

// Expose addMember for test access (reka-ui Select is hard to trigger in JSDOM)
defineExpose({ addMember, availableMembers })
</script>

<template>
  <Dialog
    :open="props.open"
    @update:open="emit('update:open', $event)"
  >
    <DialogContent :show-close-button="true" class="max-w-lg">
      <DialogHeader>
        <DialogTitle>{{ groupName }} — Members</DialogTitle>
        <DialogDescription>
          Manage members of this group.
        </DialogDescription>
      </DialogHeader>

      <div class="space-y-4 py-2" aria-live="polite">
        <!-- Loading state -->
        <div v-if="loading" class="flex items-center justify-center py-8 text-muted-foreground">
          <Loader2 class="mr-2 size-5 animate-spin" aria-hidden="true" />
          Loading members...
        </div>

        <div v-else-if="fetchError" class="py-6 text-center text-sm text-destructive" role="alert">
          {{ fetchError }}
        </div>

        <template v-else>
          <!-- Action error display -->
          <p v-if="actionError" class="text-sm text-destructive" role="alert">{{ actionError }}</p>

          <!-- Add member section -->
          <div v-if="availableMembers.length > 0" class="flex items-center gap-2">
            <Select :model-value="selectedUserId" @update:model-value="handleSelectAdd">
              <SelectTrigger data-testid="add-member-select" class="flex-1">
                <SelectValue placeholder="Add a member..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem
                  v-for="m in availableMembers"
                  :key="m.user_id"
                  :value="m.user_id"
                >
                  {{ m.display_name }} ({{ m.email }})
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <!-- Members list -->
          <div v-if="groupMembers.length === 0" class="py-6 text-center text-sm text-muted-foreground">
            No members in this group yet.
          </div>

          <div v-else class="divide-y">
            <div
              v-for="m in groupMembers"
              :key="m.user_id"
              class="flex items-center justify-between py-2"
            >
              <div>
                <p class="text-sm font-medium">{{ m.display_name }}</p>
                <p class="text-xs text-muted-foreground">{{ m.email }}</p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                aria-label="Remove member"
                data-testid="remove-group-member-btn"
                @click="removeMember(m.user_id)"
              >
                <Trash2 class="size-4 text-destructive" />
              </Button>
            </div>
          </div>
        </template>
      </div>
    </DialogContent>
  </Dialog>
</template>
