/**
 * Key derivation functions.
 *
 * HKDF-SHA256 (RFC 5869) — Derive KEK from ECDH shared secret.
 * HMAC-SHA256 (RFC 2104) — Approval tokens.
 *
 * Uses Node.js built-in crypto only.
 */

import { createHash, createHmac, hkdfSync } from 'node:crypto';

/** Protocol version prefix for HKDF info parameter */
const KEK_VERSION = 'clavum-kek-v1';

export const kdf = {
  /**
   * Derive a KEK from ECDH shared secret.
   *
   * KEK = HKDF-SHA256(ikm, salt, "clavum-kek-v1" ‖ secretId, 32)
   *
   * @param ikm - Input key material (ECDH shared secret, or K_agent ‖ K_phone for red)
   * @param salt - Per-secret random salt (green/yellow) or challenge (red)
   * @param secretId - UUID of the secret (domain separation)
   */
  deriveKek(ikm: Uint8Array, salt: Uint8Array, secretId: string): Uint8Array {
    const info = `${KEK_VERSION}${secretId}`;
    const derived = hkdfSync('sha256', ikm, salt, info, 32);
    return new Uint8Array(derived);
  },

  /**
   * Derive a fingerprint for pairing verification.
   *
   * fingerprint = HKDF-SHA256(sharedSecret, "clavum-fingerprint", "verify", 4)
   * → 4 bytes → mapped to 4 emoji (32 bits of security)
   */
  deriveFingerprint(sharedSecret: Uint8Array): Uint8Array {
    const derived = hkdfSync('sha256', sharedSecret, 'clavum-fingerprint', 'verify', 4);
    return new Uint8Array(derived);
  },

  /**
   * HMAC-SHA256 for approval tokens.
   */
  hmac(key: Uint8Array, message: Uint8Array): Uint8Array {
    const mac = createHmac('sha256', key).update(message).digest();
    return new Uint8Array(mac);
  },

  /**
   * SHA-256 hash.
   */
  hash(data: Uint8Array): Uint8Array {
    const digest = createHash('sha256').update(data).digest();
    return new Uint8Array(digest);
  },
};
