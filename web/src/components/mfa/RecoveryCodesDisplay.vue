<!-- ABOUTME: Shows one-time MFA recovery codes once, with copy and download, and requires acknowledgment. -->
<!-- ABOUTME: Emits 'done' after the user confirms the codes are saved (or immediately if none were returned). -->

<script setup lang="ts">
import { computed, ref } from 'vue'
import { Button } from '@/components/ui/button'

const props = defineProps<{ codes: string[] }>()
const emit = defineEmits<{ done: [] }>()

const saved = ref(false)
const copied = ref(false)
const hasCodes = computed(() => props.codes.length > 0)
const codesText = computed(() => props.codes.join('\n'))

async function copyCodes() {
  await navigator.clipboard.writeText(codesText.value)
  copied.value = true
}

function downloadCodes() {
  const text = `CVErt Ops recovery codes\nEach code can be used once.\n\n${codesText.value}\n`
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  const link = document.createElement('a')
  link.href = url
  link.download = 'cvert-ops-recovery-codes.txt'
  link.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <div class="space-y-4">
    <template v-if="hasCodes">
      <p class="text-sm text-muted-foreground">
        Save these recovery codes somewhere safe. Each code signs you in once if you lose access to your
        second factor. They will not be shown again.
      </p>
      <ul class="grid grid-cols-2 gap-2 rounded-md border bg-muted/40 p-3 font-mono text-sm" aria-label="Recovery codes">
        <li v-for="code in props.codes" :key="code">{{ code }}</li>
      </ul>
      <div class="flex gap-2">
        <Button type="button" variant="outline" data-testid="copy-recovery-codes" @click="copyCodes">
          {{ copied ? 'Copied' : 'Copy all' }}
        </Button>
        <Button type="button" variant="outline" data-testid="download-recovery-codes" @click="downloadCodes">
          Download .txt
        </Button>
      </div>
      <label class="flex items-start gap-2 text-sm">
        <input id="recovery-codes-saved" v-model="saved" type="checkbox" class="mt-0.5 size-4 accent-primary" />
        <span>I have saved these recovery codes</span>
      </label>
    </template>
    <p v-else class="text-sm text-destructive" role="alert">
      Recovery codes could not be generated. Generate new ones from your account page so you can still sign in
      if you lose your second factor.
    </p>
    <Button
      type="button"
      class="w-full"
      data-testid="recovery-codes-done"
      :disabled="hasCodes && !saved"
      @click="emit('done')"
    >
      Continue
    </Button>
  </div>
</template>
