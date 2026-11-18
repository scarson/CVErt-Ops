<!-- ABOUTME: Account settings page for the signed-in user: password and two-factor authentication. -->
<!-- ABOUTME: When a password change is required, shows only that, since the server blocks everything else. -->

<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import ChangePasswordCard from '@/components/account/ChangePasswordCard.vue'
import MfaSettingsCard from '@/components/account/MfaSettingsCard.vue'

const auth = useAuthStore()
</script>

<template>
  <div class="mx-auto max-w-3xl space-y-6">
    <h1 class="text-2xl font-semibold">Account</h1>

    <p
      v-if="auth.user?.force_password_reset"
      class="rounded-md border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive"
      role="alert"
    >
      An administrator requires you to change your password. You must change your password before you can
      continue.
    </p>

    <ChangePasswordCard />
    <MfaSettingsCard v-if="!auth.user?.force_password_reset" />
  </div>
</template>
