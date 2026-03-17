<!-- ABOUTME: Dialog for inviting a member to the organization with email and role selection. -->
<!-- ABOUTME: Emits 'invited' with the invitation entry on success; role options are RBAC-restricted. -->

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
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { UserPlus } from 'lucide-vue-next'

export interface InvitationEntry {
  id: string
  email: string
  role: string
  expires_at: string
  created_at: string
}

const ROLE_HIERARCHY: Record<string, number> = {
  owner: 4,
  admin: 3,
  member: 2,
  viewer: 1,
}

const INVITABLE_ROLES = ['admin', 'member', 'viewer'] as const

const props = defineProps<{
  open: boolean
  currentUserRole: string
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
  invited: [entry: InvitationEntry]
}>()

const auth = useAuthStore()
const email = ref('')
const role = ref('member')
const submitting = ref(false)
const error = ref('')
const success = ref(false)

const availableRoles = computed(() => {
  const myLevel = ROLE_HIERARCHY[props.currentUserRole] ?? 0
  return INVITABLE_ROLES.filter((r) => ROLE_HIERARCHY[r]! < myLevel)
})

function resetForm() {
  email.value = ''
  role.value = 'member'
  error.value = ''
  success.value = false
  submitting.value = false
}

watch(
  () => props.open,
  (isOpen) => {
    if (!isOpen) {
      resetForm()
    }
  },
)

async function handleSend() {
  if (!email.value.trim() || submitting.value) return

  submitting.value = true
  error.value = ''

  try {
    const { data, error: fetchError } = await client.POST('/orgs/{org_id}/invitations', {
      params: { path: { org_id: auth.activeOrgId! } },
      body: { email: email.value.trim(), role: role.value },
    })

    if (fetchError) {
      error.value = fetchError.detail ?? 'Failed to send invitation'
      submitting.value = false
      return
    }

    success.value = true
    emit('invited', data as InvitationEntry)
  } catch {
    error.value = 'Network error. Please try again.'
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <Dialog
    :open="props.open"
    @update:open="emit('update:open', $event)"
  >
    <DialogContent :show-close-button="true">
      <DialogHeader>
        <DialogTitle>Invite Member</DialogTitle>
        <DialogDescription>
          Send an invitation to join this organization.
        </DialogDescription>
      </DialogHeader>

      <div class="space-y-4 py-2">
        <div v-if="success" data-testid="invite-success" class="rounded-md bg-green-50 p-3 text-sm text-green-800 dark:bg-green-950 dark:text-green-200">
          <div class="flex items-center gap-2">
            <UserPlus class="size-4" aria-hidden="true" />
            Invitation sent successfully
          </div>
        </div>

        <template v-if="!success">
          <div class="space-y-2">
            <Label for="invite-email">Email address</Label>
            <Input
              id="invite-email"
              v-model="email"
              type="email"
              data-testid="invite-email-input"
              placeholder="user@example.com"
              :disabled="submitting"
              :aria-invalid="!!error || undefined"
              :aria-describedby="error ? 'invite-error' : undefined"
            />
          </div>

          <div class="space-y-2">
            <Label for="invite-role">Role</Label>
            <Select v-model="role">
              <SelectTrigger data-testid="invite-role-trigger">
                <SelectValue placeholder="Select role" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem
                  v-for="r in availableRoles"
                  :key="r"
                  :value="r"
                  :data-testid="`invite-role-option-${r}`"
                >
                  {{ r.charAt(0).toUpperCase() + r.slice(1) }}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <p v-if="error" id="invite-error" class="text-sm text-destructive" role="alert" data-testid="invite-error">
            {{ error }}
          </p>
        </template>
      </div>

      <DialogFooter>
        <Button
          variant="outline"
          :disabled="submitting"
          @click="emit('update:open', false)"
        >
          {{ success ? 'Close' : 'Cancel' }}
        </Button>
        <Button
          v-if="!success"
          data-testid="send-invite-btn"
          :disabled="!email.trim() || submitting"
          @click="handleSend"
        >
          {{ submitting ? 'Sending...' : 'Send Invitation' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
