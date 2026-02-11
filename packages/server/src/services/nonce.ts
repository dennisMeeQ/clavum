/**
 * Nonce deduplication service.
 *
 * Stores signature hashes to prevent request replay attacks.
 * Expired nonces are cleaned up lazily on every Nth request.
 */

import { prisma } from '../db.js';

/** Clean up expired nonces every N calls to storeNonce. */
const CLEANUP_INTERVAL = 50;
let callCount = 0;

/**
 * Store a nonce (signature hash) with an expiry time.
 * Triggers lazy cleanup every CLEANUP_INTERVAL calls.
 */
export async function storeNonce(signatureHash: string, expiresAt: Date): Promise<void> {
  await prisma.usedNonce.create({
    data: {
      nonce: signatureHash,
      expiresAt,
    },
  });

  callCount++;
  if (callCount >= CLEANUP_INTERVAL) {
    callCount = 0;
    // Fire-and-forget cleanup — don't block the request
    cleanExpired().catch(() => {});
  }
}

/**
 * Check if a signature hash has been seen before (replay detection).
 */
export async function isReplay(signatureHash: string): Promise<boolean> {
  const existing = await prisma.usedNonce.findUnique({
    where: { nonce: signatureHash },
  });
  return existing !== null;
}

/**
 * Delete all nonces that have expired.
 * Returns the count of deleted records.
 */
export async function cleanExpired(): Promise<number> {
  const result = await prisma.usedNonce.deleteMany({
    where: {
      expiresAt: { lt: new Date() },
    },
  });
  return result.count;
}
