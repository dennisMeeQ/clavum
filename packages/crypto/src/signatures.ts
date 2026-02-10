/**
 * Request signing and approval verification.
 *
 * Uses Node.js built-in crypto only.
 */

import { randomBytes } from 'node:crypto';
import { kdf } from './kdf.js';
import { ed25519 } from './keys.js';

const encoder = new TextEncoder();

export const signatures = {
  /**
   * Sign an API request.
   *
   * Payload: timestamp ‖ ":" ‖ method ‖ ":" ‖ path ‖ ":" ‖ hex(SHA256(body))
   */
  signRequest(
    privateKey: Uint8Array,
    timestamp: string,
    method: string,
    path: string,
    body: Uint8Array,
  ): Uint8Array {
    const bodyHash = kdf.hash(body);
    const payload = encoder.encode(
      `${timestamp}:${method}:${path}:${Buffer.from(bodyHash).toString('hex')}`,
    );
    return ed25519.sign(privateKey, payload);
  },

  /**
   * Verify an API request signature.
   * Returns false if timestamp is outside the 60-second replay window.
   */
  verifyRequest(
    publicKey: Uint8Array,
    timestamp: string,
    method: string,
    path: string,
    body: Uint8Array,
    signature: Uint8Array,
    maxAgeMs: number = 60_000,
  ): boolean {
    // Check replay window
    const requestTime = Number.parseInt(timestamp, 10);
    const now = Date.now();
    if (Number.isNaN(requestTime) || Math.abs(now - requestTime) > maxAgeMs) {
      return false;
    }

    const bodyHash = kdf.hash(body);
    const payload = encoder.encode(
      `${timestamp}:${method}:${path}:${Buffer.from(bodyHash).toString('hex')}`,
    );
    return ed25519.verify(publicKey, payload, signature);
  },

  /**
   * Build a context-bound challenge.
   *
   * challenge = random(32) ‖ secretId ‖ SHA256(reason)
   */
  buildChallenge(secretId: string, reason: string, nonce?: Uint8Array): Uint8Array {
    const actualNonce = nonce ?? randomBytes(32);
    const secretIdBytes = encoder.encode(secretId);
    const reasonHash = kdf.hash(encoder.encode(reason));

    const challenge = new Uint8Array(32 + secretIdBytes.length + 32);
    challenge.set(actualNonce, 0);
    challenge.set(secretIdBytes, 32);
    challenge.set(reasonHash, 32 + secretIdBytes.length);
    return challenge;
  },

  /**
   * Sign an approval challenge (phone side).
   */
  signApproval(privateKey: Uint8Array, challenge: Uint8Array): Uint8Array {
    return ed25519.sign(privateKey, challenge);
  },

  /**
   * Verify an approval signature (server side).
   */
  verifyApproval(publicKey: Uint8Array, challenge: Uint8Array, signature: Uint8Array): boolean {
    return ed25519.verify(publicKey, challenge, signature);
  },
};
