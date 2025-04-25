import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Normalize URL by adding http:// if protocol is missing
 */
export function normalizeUrl(url: string): string {
  if (!url) return url

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return `http://${url}`
  }

  return url
}
