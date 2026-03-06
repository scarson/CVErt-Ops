// ABOUTME: UI store for cross-component state (sidebar collapse).
// ABOUTME: Toast notifications use Sonner directly — no store needed.

import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useUIStore = defineStore('ui', () => {
  const sidebarCollapsed = ref(false)

  function toggleSidebar() {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }

  return {
    sidebarCollapsed,
    toggleSidebar,
  }
})
