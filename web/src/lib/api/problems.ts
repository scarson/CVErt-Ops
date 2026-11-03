// ABOUTME: Helpers for reading RFC 9457 problem responses returned by the API client.
// ABOUTME: Lets callers branch on the problem type instead of the status code or detail text.

/** The sign-in session (pending token) is missing, expired, or belongs to another user. */
export const PROBLEM_PENDING_SESSION_INVALID = 'urn:cvert:error:pending-session-invalid'
/** A submitted MFA or enrollment code was wrong. */
export const PROBLEM_INVALID_CODE = 'urn:cvert:error:invalid-code'
/** A submitted current password was wrong. */
export const PROBLEM_INVALID_PASSWORD = 'urn:cvert:error:invalid-password'
/** The TOTP enrollment step expired; setup must run again. */
export const PROBLEM_ENROLLMENT_EXPIRED = 'urn:cvert:error:enrollment-expired'
/** The account must change its password before using the app. */
export const PROBLEM_PASSWORD_CHANGE_REQUIRED = 'password_change_required'

/** Returns the problem type, or undefined for untyped (`about:blank`) problems. */
export function problemType(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const type = (error as { type?: unknown }).type
  if (typeof type !== 'string' || type === '' || type === 'about:blank') return undefined
  return type
}

/** Returns the problem detail, or the fallback when the error carries none. */
export function problemDetail(error: unknown, fallback: string): string {
  if (typeof error !== 'object' || error === null) return fallback
  const detail = (error as { detail?: unknown }).detail
  return typeof detail === 'string' && detail !== '' ? detail : fallback
}
