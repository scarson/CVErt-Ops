// ABOUTME: Utility functions shared across the frontend.
// ABOUTME: cn() merges Tailwind CSS classes with proper precedence.

import type { ClassValue } from "clsx"
import { clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Returns the URL if it uses a safe scheme (http/https), or '#' otherwise.
 * Prevents javascript: and data: URL injection in user-controllable href attributes.
 */
export function safeHref(url: string): string {
  try {
    const parsed = new URL(url)
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return url
    }
    return '#'
  } catch {
    return '#'
  }
}
