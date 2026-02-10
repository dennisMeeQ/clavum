/**
 * Composite cryptographic flows for Clavum.
 *
 * Green tier: server + agent ephemeral ECDH → KEK
 * Red tier: agent + phone + server three-party → KEK
 */

import { aes256gcm } from './aes.js';
import { kdf } from './kdf.js';
import { x25519 } from './keys.js';
import { concat } from './utils.js';

export const flows = {
  /**
   * Derive a Green-tier KEK from agent ephemeral + server public key.
   *
   * KEK = HKDF-SHA256(X25519(ephPriv, serverPub), kekSalt, secretId)
   */
  deriveGreenKek(
    ephPriv: Uint8Array,
    serverPub: Uint8Array,
    kekSalt: Uint8Array,
    secretId: string,
  ): Uint8Array {
    const shared = x25519.sharedSecret(ephPriv, serverPub);
    return kdf.deriveKek(shared, kekSalt, secretId);
  },

  /**
   * Derive a Red-tier KEK from pre-derived shared secrets + challenge.
   *
   * KEK = HKDF-SHA256(K_agent ‖ K_phone, challenge, secretId)
   *
   * @param kAgent - Pre-derived ECDH shared secret (agent ↔ server)
   * @param kPhone - Pre-derived ECDH shared secret (phone ↔ server)
   * @param challenge - Context-bound challenge bytes
   * @param secretId - UUID of the secret
   */
  deriveRedKek(
    kAgent: Uint8Array,
    kPhone: Uint8Array,
    challenge: Uint8Array,
    secretId: string,
  ): Uint8Array {
    const ikm = concat(kAgent, kPhone);
    return kdf.deriveKek(ikm, challenge, secretId);
  },

  /**
   * Wrap a DEK with a KEK using AES-256-GCM.
   */
  wrapDek(
    kek: Uint8Array,
    dek: Uint8Array,
    aad: Uint8Array = new Uint8Array(0),
  ): { encryptedDek: Uint8Array; dekIv: Uint8Array; dekTag: Uint8Array } {
    const { ciphertext, iv, tag } = aes256gcm.encrypt(kek, dek, aad);
    return { encryptedDek: ciphertext, dekIv: iv, dekTag: tag };
  },

  /**
   * Unwrap a DEK with a KEK using AES-256-GCM.
   */
  unwrapDek(
    kek: Uint8Array,
    encryptedDek: Uint8Array,
    dekIv: Uint8Array,
    aad: Uint8Array,
    dekTag: Uint8Array,
  ): Uint8Array {
    return aes256gcm.decrypt(kek, encryptedDek, dekIv, aad, dekTag);
  },

  /**
   * Encrypt a secret's plaintext with a DEK using AES-256-GCM.
   */
  encryptSecret(
    dek: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array = new Uint8Array(0),
  ): { encryptedBlob: Uint8Array; blobIv: Uint8Array; blobTag: Uint8Array } {
    const { ciphertext, iv, tag } = aes256gcm.encrypt(dek, plaintext, aad);
    return { encryptedBlob: ciphertext, blobIv: iv, blobTag: tag };
  },

  /**
   * Decrypt a secret's ciphertext with a DEK using AES-256-GCM.
   */
  decryptSecret(
    dek: Uint8Array,
    encryptedBlob: Uint8Array,
    blobIv: Uint8Array,
    aad: Uint8Array,
    blobTag: Uint8Array,
  ): Uint8Array {
    return aes256gcm.decrypt(dek, encryptedBlob, blobIv, aad, blobTag);
  },
};
