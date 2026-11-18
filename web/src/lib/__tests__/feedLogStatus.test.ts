// ABOUTME: Tests for the badge variant chosen for a feed fetch log status.
// ABOUTME: A partial run is a normal backfill slice, so it must not render as an error.

import { describe, it, expect } from 'vitest'
import { feedLogBadgeVariant } from '@/lib/feedLogStatus'

describe('feedLogBadgeVariant', () => {
  it('shows success as the default variant', () => {
    expect(feedLogBadgeVariant('success')).toBe('default')
  })

  it('shows partial as neutral, not as an error', () => {
    expect(feedLogBadgeVariant('partial')).toBe('secondary')
  })

  it('shows error as destructive', () => {
    expect(feedLogBadgeVariant('error')).toBe('destructive')
  })

  it('shows an unrecognized status as destructive', () => {
    expect(feedLogBadgeVariant('unexpected')).toBe('destructive')
  })
})
