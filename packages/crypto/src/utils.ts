/**
 * Utility functions for @clavum/crypto.
 *
 * Uses Node.js built-in crypto only.
 */

import { timingSafeEqual as nodeTimingSafeEqual } from 'node:crypto';

/**
 * Securely wipe a buffer by overwriting with zeros.
 * Use after key material is no longer needed.
 */
export function wipe(buffer: Uint8Array): void {
  buffer.fill(0);
}

/**
 * Concatenate multiple Uint8Arrays into a single Uint8Array.
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) {
    totalLength += arr.length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Constant-time comparison of two Uint8Arrays.
 * Returns false if lengths differ (not constant-time for length, but
 * this is acceptable — length is not secret in our protocol).
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return nodeTimingSafeEqual(a, b);
}

/**
 * Encode bytes to base64url (RFC 4648 §5, no padding).
 */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * Decode base64url string to bytes.
 */
export function fromBase64Url(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}
