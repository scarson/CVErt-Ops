<!-- ABOUTME: Account page card for two-factor authentication: enrolled methods, requirements, and recovery codes. -->
<!-- ABOUTME: Adds methods via MfaEnrollment; removal and code regeneration require the current password. -->

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import client from '@/lib/api/client'
import type { components } from '@/lib/api/schema'
import { PROBLEM_INVALID_PASSWORD, problemDetail, problemType } from '@/lib/api/problems'
import { useAuthStore } from '@/stores/auth'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import MfaEnrollment from '@/components/mfa/MfaEnrollment.vue'
import RecoveryCodesDisplay from '@/components/mfa/RecoveryCodesDisplay.vue'
import PasswordConfirmDialog from './PasswordConfirmDialog.vue'

type MfaStatus = components['schemas']['MfaMethodsOutputBody']
type RequiredReason = components['schemas']['MFARequiredReason']
type PasswordAction = { kind: 'remove'; method: string } | { kind: 'regenerate' }

const METHOD_LABELS: Record<string, string> = {
  totp: 'Authenticator app',
  email_otp: 'Email codes',
}
// Matches the server's "running low" threshold for recovery codes.
const LOW_RECOVERY_CODES = 2

const auth = useAuthStore()

const status = ref<MfaStatus | null>(null)
const loadError = ref('')
const adding = ref(false)
const shownCodes = ref<string[] | null>(null)
const action = ref<PasswordAction | null>(null)
const actionBusy = ref(false)
const actionError = ref('')

const methods = computed(() => status.value?.methods ?? [])
const enrolledMethodNames = computed(() => methods.value.map((m) => m.method))
const canAddMethod = computed(() => enrolledMethodNames.value.length < Object.keys(METHOD_LABELS).length)
const hasPassword = computed(() => auth.user?.has_password === true)

function describeReason(reason: RequiredReason): string {
  switch (reason.source) {
    case 'site_admin':
      return 'you are a site administrator'
    case 'org_owner':
      return 'you own an organization'
    case 'org_policy':
      return `${reason.org_name} requires it for all members`
    case 'per_member':
      return `${reason.org_name} requires it for your membership`
    default:
      return 'the requirement could not be checked, so it is treated as required'
  }
}

const requiredText = computed(() => (status.value?.required_reasons ?? []).map(describeReason).join('; '))

async function loadStatus() {
  const { data, error } = await client.GET('/auth/mfa/methods')
  if (error || !data) {
    loadError.value = problemDetail(error, 'Could not load two-factor settings')
    return
  }
  loadError.value = ''
  status.value = data
}

onMounted(loadStatus)

function onEnrolled(codes: string[]) {
  adding.value = false
  // Codes come only with the first method; a first method without codes means generation failed.
  if (methods.value.length === 0 || codes.length > 0) {
    shownCodes.value = codes
    return
  }
  loadStatus()
}

function onCodesSaved() {
  shownCodes.value = null
  loadStatus()
}

function openAction(next: PasswordAction) {
  actionError.value = ''
  action.value = next
}

const dialogText = computed(() => {
  const current = action.value
  if (current?.kind === 'remove') {
    return {
      title: `Remove ${METHOD_LABELS[current.method] ?? current.method}`,
      description: 'Enter your current password to remove this method.',
      confirmLabel: 'Remove',
    }
  }
  return {
    title: 'Generate new recovery codes',
    description: 'Your existing recovery codes stop working. Enter your current password to continue.',
    confirmLabel: 'Generate',
  }
})

async function runAction(password: string) {
  const current = action.value
  if (!current) return
  actionBusy.value = true
  actionError.value = ''
  const result =
    current.kind === 'remove'
      ? await client.DELETE('/auth/mfa/methods/{method}', {
          params: { path: { method: current.method as 'totp' | 'email_otp' } },
          body: { current_password: password },
        })
      : await client.POST('/auth/mfa/recovery-codes/regenerate', { body: { current_password: password } })
  actionBusy.value = false
  if (result.error) {
    actionError.value =
      problemType(result.error) === PROBLEM_INVALID_PASSWORD
        ? 'Your password is not correct.'
        : problemDetail(result.error, 'The change could not be made')
    return
  }
  action.value = null
  if (current.kind === 'regenerate') {
    const data = result.data as { recovery_codes?: string[] | null } | undefined
    shownCodes.value = data?.recovery_codes ?? []
    return
  }
  loadStatus()
}
</script>

<template>
  <Card>
    <CardHeader>
      <CardTitle>Two-factor authentication</CardTitle>
      <CardDescription>A second step at sign-in protects your account if your password leaks.</CardDescription>
    </CardHeader>
    <CardContent class="space-y-6">
      <p v-if="loadError" class="text-sm text-destructive" role="alert">{{ loadError }}</p>

      <RecoveryCodesDisplay v-if="shownCodes" :codes="shownCodes" class="max-w-md" @done="onCodesSaved" />

      <template v-else-if="status">
        <p v-if="status.required" class="text-sm">Required because {{ requiredText }}.</p>

        <section aria-labelledby="mfa-methods-heading" class="space-y-2">
          <h3 id="mfa-methods-heading" class="text-sm font-medium">Methods</h3>
          <p v-if="methods.length === 0" class="text-sm text-muted-foreground">
            Two-factor authentication is off.
          </p>
          <ul v-else class="divide-y rounded-md border">
            <li v-for="m in methods" :key="m.method" class="flex items-center justify-between gap-4 px-3 py-2 text-sm">
              <span>
                {{ METHOD_LABELS[m.method] ?? m.method }}
                <span class="text-muted-foreground">· added {{ new Date(m.created_at).toLocaleDateString() }}</span>
              </span>
              <Button
                v-if="hasPassword"
                size="sm"
                variant="outline"
                :data-testid="`remove-${m.method}`"
                @click="openAction({ kind: 'remove', method: m.method })"
              >
                Remove
              </Button>
            </li>
          </ul>
          <div v-if="adding" class="max-w-md rounded-md border p-4">
            <MfaEnrollment
              :enrolled-methods="enrolledMethodNames"
              @enrolled="onEnrolled"
              @session-expired="loadError = 'Your session changed. Reload the page and try again.'"
            />
            <Button variant="ghost" size="sm" class="mt-2" @click="adding = false">Cancel</Button>
          </div>
          <Button v-else-if="canAddMethod" variant="outline" data-testid="add-mfa-method" @click="adding = true">
            Add a method
          </Button>
        </section>

        <section v-if="methods.length > 0" aria-labelledby="recovery-codes-heading" class="space-y-2">
          <h3 id="recovery-codes-heading" class="text-sm font-medium">Recovery codes</h3>
          <p class="text-sm text-muted-foreground">
            {{ status.recovery_codes_remaining }} recovery codes left.
          </p>
          <p
            v-if="status.recovery_codes_remaining <= LOW_RECOVERY_CODES"
            class="text-sm text-destructive"
            data-testid="recovery-codes-low"
          >
            You are running out of recovery codes. Generate new ones.
          </p>
          <Button
            v-if="hasPassword"
            variant="outline"
            data-testid="regenerate-recovery-codes"
            @click="openAction({ kind: 'regenerate' })"
          >
            Generate new recovery codes
          </Button>
        </section>

        <p v-if="!hasPassword && methods.length > 0" class="text-sm text-muted-foreground">
          Removing a method or generating recovery codes need a password, and this account signs in through an
          external identity provider. Ask an administrator to reset two-factor authentication if you need to.
        </p>
      </template>
    </CardContent>
  </Card>

  <PasswordConfirmDialog
    :open="action !== null"
    :title="dialogText.title"
    :description="dialogText.description"
    :confirm-label="dialogText.confirmLabel"
    :busy="actionBusy"
    :error="actionError"
    @update:open="(open) => { if (!open) action = null }"
    @confirm="runAction"
  />
</template>
