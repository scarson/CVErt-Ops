// ABOUTME: Tests for shared utility functions.
// ABOUTME: Covers safeHref URL sanitization for XSS prevention.

import { describe, it, expect } from 'vitest'
import { safeHref } from '../utils'

describe('safeHref', () => {
  it('allows https URLs', () => {
    expect(safeHref('https://nvd.nist.gov/vuln/detail/CVE-2024-001')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2024-001')
  })

  it('allows http URLs', () => {
    expect(safeHref('http://example.com')).toBe('http://example.com')
  })

  it('blocks javascript: URLs', () => {
    expect(safeHref('javascript:alert(1)')).toBe('#')
  })

  it('blocks data: URLs', () => {
    expect(safeHref('data:text/html,<h1>hi</h1>')).toBe('#')
  })

  it('handles malformed URLs', () => {
    expect(safeHref('not a url')).toBe('#')
  })
})
