// ABOUTME: Tests for new-password validation shared by password change forms.
// ABOUTME: Verifies the minimum length and the confirmation match.

import { describe, it, expect } from 'vitest'
import { MIN_PASSWORD_LENGTH, validateNewPassword } from '../password'

describe('validateNewPassword', () => {
  it('matches the backend minimum of 16 characters', () => {
    expect(MIN_PASSWORD_LENGTH).toBe(16)
  })

  it('rejects a short password', () => {
    expect(validateNewPassword('fifteen-chars-x', 'fifteen-chars-x')).toBe(
      'Password must be at least 16 characters',
    )
  })

  it('rejects a mismatched confirmation', () => {
    expect(validateNewPassword('sixteen-chars-ab', 'sixteen-chars-ac')).toBe('Passwords do not match')
  })

  it('accepts a valid password', () => {
    expect(validateNewPassword('sixteen-chars-ab', 'sixteen-chars-ab')).toBe('')
  })
})
