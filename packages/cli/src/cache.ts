/**
 * In-memory DEK cache for Clavum CLI.
 *
 * Caches decrypted DEKs to avoid repeated server calls.
 * Only effective in library/daemon mode — each CLI invocation starts fresh.
 *
 * Default TTL: 4 hours.
 */

import { wipe } from '@clavum/crypto';

interface CacheEntry {
  dek: Uint8Array;
  expiresAt: number;
}

const DEFAULT_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours

const store = new Map<string, CacheEntry>();

/**
 * Get a cached DEK. Returns null if not found or expired.
 * Wipes and removes expired entries automatically.
 */
export function get(secretId: string): Uint8Array | null {
  const entry = store.get(secretId);
  if (!entry) return null;

  if (Date.now() >= entry.expiresAt) {
    wipe(entry.dek);
    store.delete(secretId);
    return null;
  }

  return entry.dek;
}

/**
 * Cache a DEK for a secret.
 */
export function set(secretId: string, dek: Uint8Array, ttlMs: number = DEFAULT_TTL_MS): void {
  // Wipe existing entry if present
  const existing = store.get(secretId);
  if (existing) {
    wipe(existing.dek);
  }

  store.set(secretId, {
    dek: new Uint8Array(dek), // Copy so caller can wipe original
    expiresAt: Date.now() + ttlMs,
  });
}

/**
 * Clear all cached DEKs, wiping each from memory.
 */
export function clear(): void {
  for (const entry of store.values()) {
    wipe(entry.dek);
  }
  store.clear();
}

export const dekCache = { get, set, clear };
