// ABOUTME: Utility functions shared across the frontend.
// ABOUTME: cn() merges Tailwind CSS classes with proper precedence.

import type { ClassValue } from "clsx"
import { clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
