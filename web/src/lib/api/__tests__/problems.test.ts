// ABOUTME: Tests for RFC 9457 problem helpers.
// ABOUTME: Verifies problem type and detail extraction from API client errors.

import { describe, it, expect } from 'vitest'
import { problemDetail, problemType, PROBLEM_INVALID_CODE } from '../problems'

describe('problemType', () => {
  it('returns the type of a typed problem', () => {
    expect(problemType({ type: PROBLEM_INVALID_CODE, status: 401 })).toBe(PROBLEM_INVALID_CODE)
  })

  it('returns undefined for untyped problems and non-objects', () => {
    expect(problemType({ type: 'about:blank', status: 401 })).toBeUndefined()
    expect(problemType({ status: 401 })).toBeUndefined()
    expect(problemType(undefined)).toBeUndefined()
    expect(problemType('boom')).toBeUndefined()
  })
})

describe('problemDetail', () => {
  it('returns the detail when present', () => {
    expect(problemDetail({ detail: 'invalid verification code' }, 'fallback')).toBe('invalid verification code')
  })

  it('returns the fallback when there is no detail', () => {
    expect(problemDetail({}, 'fallback')).toBe('fallback')
    expect(problemDetail(undefined, 'fallback')).toBe('fallback')
  })
})
