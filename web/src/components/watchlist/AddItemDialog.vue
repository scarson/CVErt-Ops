<!-- ABOUTME: Dialog for adding package or CPE items to a watchlist. -->
<!-- ABOUTME: Supports ecosystem selection for packages and CPE URI input for CPE items. -->

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { orgFetch } from '@/lib/api/orgFetch'
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
import { Package, Cpu } from 'lucide-vue-next'

export interface WatchlistItemEntry {
  id: string
  item_type: 'package' | 'cpe'
  ecosystem?: string
  package_name?: string
  namespace?: string
  cpe_normalized?: string
  created_at: string
}

const ECOSYSTEMS = [
  'npm',
  'pypi',
  'maven',
  'go',
  'cargo',
  'rubygems',
  'nuget',
  'hex',
  'pub',
  'swift',
  'cocoapods',
  'packagist',
] as const

const props = defineProps<{
  open: boolean
  watchlistId: string
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
  added: [item: WatchlistItemEntry]
}>()

const auth = useAuthStore()

const itemType = ref<'package' | 'cpe'>('package')
const ecosystem = ref('')
const packageName = ref('')
const namespace = ref('')
const cpeNormalized = ref('')
const submitting = ref(false)
const error = ref('')

const canSubmit = computed(() => {
  if (submitting.value) return false
  if (itemType.value === 'package') {
    return ecosystem.value !== '' && packageName.value.trim() !== ''
  }
  return cpeNormalized.value.trim().startsWith('cpe:2.3:')
})

function resetForm() {
  itemType.value = 'package'
  ecosystem.value = ''
  packageName.value = ''
  namespace.value = ''
  cpeNormalized.value = ''
  error.value = ''
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

async function handleAdd() {
  if (!canSubmit.value) return

  submitting.value = true
  error.value = ''

  const body: Record<string, string> =
    itemType.value === 'package'
      ? {
          item_type: 'package',
          ecosystem: ecosystem.value,
          package_name: packageName.value.trim(),
          ...(namespace.value.trim() ? { namespace: namespace.value.trim() } : {}),
        }
      : {
          item_type: 'cpe',
          cpe_normalized: cpeNormalized.value.trim(),
        }

  try {
    const resp = await orgFetch(
      `/api/v1/orgs/${auth.activeOrgId}/watchlists/${props.watchlistId}/items`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      },
    )

    if (!resp.ok) {
      const data = await resp.json()
      error.value = data.detail ?? 'Failed to add item'
      submitting.value = false
      return
    }

    const item: WatchlistItemEntry = await resp.json()
    emit('added', item)
    emit('update:open', false)
  } catch {
    error.value = 'Network error. Please try again.'
  } finally {
    submitting.value = false
  }
}

function selectEcosystem(value: string | number | bigint | Record<string, any> | null) {
  if (typeof value === 'string') {
    ecosystem.value = value
  }
}

defineExpose({ selectEcosystem })
</script>

<template>
  <Dialog
    :open="props.open"
    data-testid="add-item-dialog"
    @update:open="emit('update:open', $event)"
  >
    <DialogContent :show-close-button="true">
      <DialogHeader>
        <DialogTitle>Add Item</DialogTitle>
        <DialogDescription>
          Add a package or CPE pattern to this watchlist.
        </DialogDescription>
      </DialogHeader>

      <div class="space-y-4 py-2">
        <!-- Item type selector -->
        <div class="space-y-2">
          <Label>Item Type</Label>
          <div class="flex gap-2">
            <Button
              data-testid="item-type-package"
              :variant="itemType === 'package' ? 'default' : 'outline'"
              size="sm"
              type="button"
              @click="itemType = 'package'"
            >
              <Package class="mr-1 size-4" aria-hidden="true" />
              Package
            </Button>
            <Button
              data-testid="item-type-cpe"
              :variant="itemType === 'cpe' ? 'default' : 'outline'"
              size="sm"
              type="button"
              @click="itemType = 'cpe'"
            >
              <Cpu class="mr-1 size-4" aria-hidden="true" />
              CPE
            </Button>
          </div>
        </div>

        <!-- Package fields -->
        <template v-if="itemType === 'package'">
          <div class="space-y-2">
            <Label for="add-item-ecosystem">Ecosystem</Label>
            <Select
              :model-value="ecosystem"
              @update:model-value="selectEcosystem"
            >
              <SelectTrigger id="add-item-ecosystem" data-testid="ecosystem-select-trigger">
                <SelectValue placeholder="Select ecosystem..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem
                  v-for="eco in ECOSYSTEMS"
                  :key="eco"
                  :value="eco"
                  :data-testid="`ecosystem-option-${eco}`"
                >
                  {{ eco }}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div class="space-y-2">
            <Label for="add-item-package-name">Package Name</Label>
            <Input
              id="add-item-package-name"
              v-model="packageName"
              data-testid="package-name-input"
              placeholder="e.g. lodash"
              :disabled="submitting"
              :aria-invalid="!!error || undefined"
              :aria-describedby="error ? 'add-item-error' : undefined"
            />
          </div>

          <div class="space-y-2">
            <Label for="add-item-namespace">Namespace (optional)</Label>
            <Input
              id="add-item-namespace"
              v-model="namespace"
              data-testid="namespace-input"
              placeholder="e.g. @types"
              :disabled="submitting"
            />
          </div>
        </template>

        <!-- CPE field -->
        <template v-if="itemType === 'cpe'">
          <div class="space-y-2">
            <Label for="add-item-cpe">CPE URI</Label>
            <Input
              id="add-item-cpe"
              v-model="cpeNormalized"
              data-testid="cpe-input"
              placeholder="cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
              :disabled="submitting"
              :aria-invalid="!!error || undefined"
              :aria-describedby="error ? 'add-item-error' : undefined"
            />
            <p class="text-muted-foreground text-xs">
              Must start with "cpe:2.3:"
            </p>
          </div>
        </template>

        <p v-if="error" id="add-item-error" class="text-destructive text-sm" role="alert" data-testid="add-item-error">
          {{ error }}
        </p>
      </div>

      <DialogFooter>
        <Button
          variant="outline"
          :disabled="submitting"
          @click="emit('update:open', false)"
        >
          Cancel
        </Button>
        <Button
          data-testid="add-item-btn"
          :disabled="!canSubmit"
          @click="handleAdd"
        >
          {{ submitting ? 'Adding...' : 'Add' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
