// ABOUTME: Keyset pagination composable with cursor stack for prev/next navigation.
// ABOUTME: Tracks cursor history so users can navigate backward through pages.

import { ref, computed } from 'vue'

export function usePagination() {
  // Stack of previous cursors (null = first page).
  const cursorStack = ref<(string | null)[]>([])
  const cursor = ref<string | null>(null)
  const nextCursor = ref<string | undefined>(undefined)

  const hasPrev = computed(() => cursorStack.value.length > 0)
  const hasNext = computed(() => nextCursor.value != null)

  function setNextCursor(value: string | undefined) {
    nextCursor.value = value
  }

  function goNext() {
    if (!nextCursor.value) return
    cursorStack.value.push(cursor.value)
    cursor.value = nextCursor.value
    nextCursor.value = undefined
  }

  function goPrev() {
    if (cursorStack.value.length === 0) return
    cursor.value = cursorStack.value.pop()!
    nextCursor.value = undefined
  }

  function reset() {
    cursor.value = null
    nextCursor.value = undefined
    cursorStack.value = []
  }

  return {
    cursor,
    hasPrev,
    hasNext,
    setNextCursor,
    goNext,
    goPrev,
    reset,
  }
}
