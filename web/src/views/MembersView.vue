<!-- ABOUTME: Organization members page — lists members with roles, invitations, and management actions. -->
<!-- ABOUTME: Admin+ can change roles, invite members, and remove members; RBAC-gated UI elements. -->

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { orgFetch } from '@/lib/api/orgFetch'
import InviteMemberDialog from '@/components/settings/InviteMemberDialog.vue'
import type { InvitationEntry } from '@/components/settings/InviteMemberDialog.vue'
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
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Plus, Trash2, Loader2 } from 'lucide-vue-next'

interface MemberEntry {
  user_id: string
  email: string
  display_name: string
  role: string
  joined_at: string
}

const ROLE_HIERARCHY: Record<string, number> = {
  owner: 4,
  admin: 3,
  member: 2,
  viewer: 1,
}

const ASSIGNABLE_ROLES = ['admin', 'member', 'viewer'] as const

const auth = useAuthStore()

const members = ref<MemberEntry[]>([])
const invitations = ref<InvitationEntry[]>([])
const loading = ref(true)
const error = ref('')
const inviteDialogOpen = ref(false)
const removeTarget = ref<MemberEntry | null>(null)
const removeDialogOpen = ref(false)
const removing = ref(false)
const removeError = ref('')
const roleChangeError = ref('')
const cancelError = ref('')

const userRole = computed(() => auth.activeOrg?.role ?? 'viewer')
const isAdmin = computed(() => ROLE_HIERARCHY[userRole.value]! >= ROLE_HIERARCHY['admin']!)

function rolesAssignableBy(callerRole: string): string[] {
  const callerLevel = ROLE_HIERARCHY[callerRole] ?? 0
  return ASSIGNABLE_ROLES.filter((r) => ROLE_HIERARCHY[r]! <= callerLevel)
}

function canChangeRole(member: MemberEntry): boolean {
  return isAdmin.value && member.role !== 'owner'
}

function canRemove(member: MemberEntry): boolean {
  return isAdmin.value && member.role !== 'owner'
}

const roleBadgeVariant: Record<string, 'default' | 'secondary' | 'outline' | 'destructive'> = {
  owner: 'default',
  admin: 'secondary',
  member: 'outline',
  viewer: 'outline',
}

function apiBase() {
  return `/api/v1/orgs/${auth.activeOrgId}`
}

async function fetchMembers() {
  loading.value = true
  error.value = ''
  invitations.value = []

  try {
    const resp = await orgFetch(`${apiBase()}/members`)

    if (!resp.ok) {
      error.value = 'Failed to load members. Please try again.'
      loading.value = false
      return
    }

    const membersData = await resp.json()
    members.value = membersData.items as MemberEntry[]

    // Fetch invitations in parallel for admin+ users
    if (isAdmin.value) {
      await fetchInvitations()
    }
  } catch {
    error.value = 'Failed to load members. Please try again.'
  } finally {
    loading.value = false
  }
}

async function fetchInvitations() {
  try {
    const resp = await orgFetch(`${apiBase()}/invitations`)

    if (resp.ok) {
      const invData = await resp.json()
      invitations.value = invData.items as InvitationEntry[]
    }
  } catch {
    // Silently fail — invitations are supplementary
  }
}

async function changeRole(userId: string, newRole: string) {
  roleChangeError.value = ''

  try {
    const resp = await orgFetch(`${apiBase()}/members/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify({ role: newRole }),
    })

    if (resp.ok) {
      const updated: MemberEntry = await resp.json()
      members.value = members.value.map((m) =>
        m.user_id === userId ? { ...m, role: updated.role } : m,
      )
    } else {
      roleChangeError.value = 'Failed to change role. Please try again.'
      // Force re-render to snap Select back to actual role value.
      members.value = [...members.value]
    }
  } catch {
    roleChangeError.value = 'Failed to change role. Please try again.'
    members.value = [...members.value]
  }
}

function promptRemove(member: MemberEntry) {
  removeTarget.value = member
  removeError.value = ''
  removeDialogOpen.value = true
}

async function confirmRemove() {
  if (!removeTarget.value || removing.value) return
  removing.value = true
  removeError.value = ''

  const userId = removeTarget.value.user_id

  try {
    const resp = await orgFetch(`${apiBase()}/members/${userId}`, {
      method: 'DELETE',
    })

    if (resp.ok) {
      members.value = members.value.filter((m) => m.user_id !== userId)
      removeDialogOpen.value = false
      removeTarget.value = null
    } else {
      removeError.value = 'Failed to remove member. Please try again.'
    }
  } catch {
    removeError.value = 'Failed to remove member. Please try again.'
  } finally {
    removing.value = false
  }
}

async function cancelInvitation(invitationId: string) {
  cancelError.value = ''

  try {
    const resp = await orgFetch(`${apiBase()}/invitations/${invitationId}`, {
      method: 'DELETE',
    })

    if (resp.ok) {
      invitations.value = invitations.value.filter((i) => i.id !== invitationId)
    } else {
      cancelError.value = 'Failed to cancel invitation. Please try again.'
    }
  } catch {
    cancelError.value = 'Failed to cancel invitation. Please try again.'
  }
}

function onInvited(entry: InvitationEntry) {
  invitations.value = [...invitations.value, entry]
}

function formatDate(dateStr: string): string {
  const date = new Date(dateStr)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

// Expose methods for test access (reka-ui Select is hard to trigger in JSDOM)
defineExpose({ changeRole, rolesAssignableBy })

onMounted(() => {
  fetchMembers()
})

watch(
  () => auth.activeOrgId,
  () => {
    fetchMembers()
  },
)
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">Members</h1>
        <p class="text-sm text-muted-foreground">
          Manage team members and roles
        </p>
      </div>
      <Button
        v-if="isAdmin"
        data-testid="invite-member-btn"
        @click="inviteDialogOpen = true"
      >
        <Plus class="mr-2 size-4" aria-hidden="true" />
        Invite Member
      </Button>
    </div>

    <div aria-live="polite">
      <!-- Loading state -->
      <div v-if="loading" class="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 class="mr-2 size-5 animate-spin" aria-hidden="true" />
        Loading members...
      </div>

      <!-- Error state -->
      <div v-else-if="error" class="py-16 text-center">
        <p class="text-sm text-destructive" role="alert">{{ error }}</p>
      </div>

      <!-- Members table -->
      <template v-else>
      <!-- Role change error -->
      <p v-if="roleChangeError" class="text-sm text-destructive" role="alert">{{ roleChangeError }}</p>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Email</TableHead>
            <TableHead>Name</TableHead>
            <TableHead class="w-36">Role</TableHead>
            <TableHead class="w-36">Joined</TableHead>
            <TableHead v-if="isAdmin" class="w-16">
              <span class="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="m in members" :key="m.user_id">
            <TableCell class="font-medium">{{ m.email }}</TableCell>
            <TableCell class="text-muted-foreground">{{ m.display_name }}</TableCell>
            <TableCell>
              <!-- Admin+ users see a select for non-owner members -->
              <Select
                v-if="canChangeRole(m)"
                :model-value="m.role"
                @update:model-value="(val) => changeRole(m.user_id, String(val))"
              >
                <SelectTrigger data-testid="role-select-trigger" class="w-28" size="sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem
                    v-for="r in rolesAssignableBy(userRole)"
                    :key="r"
                    :value="r"
                  >
                    {{ r.charAt(0).toUpperCase() + r.slice(1) }}
                  </SelectItem>
                </SelectContent>
              </Select>
              <!-- Non-admin users or owner role: plain badge -->
              <Badge
                v-else
                data-testid="member-role-badge"
                :variant="roleBadgeVariant[m.role] ?? 'outline'"
              >
                {{ m.role }}
              </Badge>
            </TableCell>
            <TableCell class="text-muted-foreground">
              {{ formatDate(m.joined_at) }}
            </TableCell>
            <TableCell v-if="isAdmin">
              <Button
                v-if="canRemove(m)"
                variant="ghost"
                size="sm"
                aria-label="Remove member"
                data-testid="remove-member-btn"
                @click="promptRemove(m)"
              >
                <Trash2 class="size-4 text-destructive" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <!-- Pending Invitations -->
      <div v-if="invitations.length > 0" class="space-y-4">
        <h2 class="text-lg font-semibold tracking-tight">Pending Invitations</h2>
        <p v-if="cancelError" class="text-sm text-destructive" role="alert">{{ cancelError }}</p>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Email</TableHead>
              <TableHead class="w-28">Role</TableHead>
              <TableHead class="w-36">Expires</TableHead>
              <TableHead class="w-16">
                <span class="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="inv in invitations" :key="inv.id">
              <TableCell class="font-medium">{{ inv.email }}</TableCell>
              <TableCell>
                <Badge :variant="roleBadgeVariant[inv.role] ?? 'outline'">
                  {{ inv.role }}
                </Badge>
              </TableCell>
              <TableCell class="text-muted-foreground">
                {{ formatDate(inv.expires_at) }}
              </TableCell>
              <TableCell>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label="Cancel invitation"
                  data-testid="cancel-invitation-btn"
                  @click="cancelInvitation(inv.id)"
                >
                  <Trash2 class="size-4 text-destructive" />
                </Button>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </div>
    </template>
    </div>

    <!-- Invite dialog -->
    <InviteMemberDialog
      :open="inviteDialogOpen"
      :current-user-role="userRole"
      @update:open="inviteDialogOpen = $event"
      @invited="onInvited"
    />

    <!-- Remove confirmation dialog -->
    <AlertDialog :open="removeDialogOpen" @update:open="removeDialogOpen = $event">
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Remove member</AlertDialogTitle>
          <AlertDialogDescription>
            They will lose access to this organization. This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <p v-if="removeError" class="text-sm text-destructive" role="alert">{{ removeError }}</p>
        <AlertDialogFooter>
          <AlertDialogCancel :disabled="removing" @click="removeDialogOpen = false">Cancel</AlertDialogCancel>
          <Button
            data-testid="confirm-remove-btn"
            variant="destructive"
            :disabled="removing"
            @click="confirmRemove"
          >
            {{ removing ? 'Removing...' : 'Remove' }}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  </div>
</template>
