// ABOUTME: Tests for the keyset pagination composable.
// ABOUTME: Covers cursor stack management, next/prev navigation, and reset behavior.

import { describe, it, expect } from 'vitest'
import { usePagination } from '@/composables/usePagination'

describe('usePagination', () => {
  it('starts with no cursor and no previous page', () => {
    const { cursor, hasPrev } = usePagination()

    expect(cursor.value).toBeNull()
    expect(hasPrev.value).toBe(false)
  })

  it('hasNext is false when nextCursor is not set', () => {
    const { hasNext } = usePagination()

    expect(hasNext.value).toBe(false)
  })

  it('hasNext is true after setNextCursor is called with a value', () => {
    const { hasNext, setNextCursor } = usePagination()

    setNextCursor('abc123')
    expect(hasNext.value).toBe(true)
  })

  it('hasNext is false after setNextCursor is called with undefined', () => {
    const { hasNext, setNextCursor } = usePagination()

    setNextCursor('abc123')
    setNextCursor(undefined)
    expect(hasNext.value).toBe(false)
  })

  it('goNext advances cursor and enables hasPrev', () => {
    const { cursor, hasPrev, hasNext, setNextCursor, goNext } = usePagination()

    setNextCursor('cursor-page2')
    goNext()

    expect(cursor.value).toBe('cursor-page2')
    expect(hasPrev.value).toBe(true)
    // hasNext should be false until a new nextCursor is set
    expect(hasNext.value).toBe(false)
  })

  it('goPrev returns to the previous cursor', () => {
    const { cursor, hasPrev, setNextCursor, goNext, goPrev } = usePagination()

    // Navigate forward twice
    setNextCursor('cursor-page2')
    goNext()
    setNextCursor('cursor-page3')
    goNext()

    expect(cursor.value).toBe('cursor-page3')

    // Go back one page
    goPrev()
    expect(cursor.value).toBe('cursor-page2')
    expect(hasPrev.value).toBe(true)

    // Go back to first page
    goPrev()
    expect(cursor.value).toBeNull()
    expect(hasPrev.value).toBe(false)
  })

  it('goPrev is a no-op when already on first page', () => {
    const { cursor, hasPrev, goPrev } = usePagination()

    goPrev()
    expect(cursor.value).toBeNull()
    expect(hasPrev.value).toBe(false)
  })

  it('goNext is a no-op when no next cursor is set', () => {
    const { cursor, goNext } = usePagination()

    goNext()
    expect(cursor.value).toBeNull()
  })

  it('reset clears all state', () => {
    const { cursor, hasPrev, hasNext, setNextCursor, goNext, reset } = usePagination()

    setNextCursor('cursor-page2')
    goNext()
    setNextCursor('cursor-page3')

    expect(cursor.value).toBe('cursor-page2')
    expect(hasPrev.value).toBe(true)
    expect(hasNext.value).toBe(true)

    reset()

    expect(cursor.value).toBeNull()
    expect(hasPrev.value).toBe(false)
    expect(hasNext.value).toBe(false)
  })
})
