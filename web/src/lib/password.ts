// ABOUTME: Client-side checks for a new password before it is sent to the server.
// ABOUTME: Mirrors the backend minimum length so users see the rule before submitting.

/** Minimum password length enforced by the backend (minLength on new_password). */
export const MIN_PASSWORD_LENGTH = 16

/** Returns an error message for an invalid new password, or '' when it is acceptable. */
export function validateNewPassword(password: string, confirmation: string): string {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`
  }
  if (password !== confirmation) {
    return 'Passwords do not match'
  }
  return ''
}
