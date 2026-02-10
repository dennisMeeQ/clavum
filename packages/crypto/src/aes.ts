/**
 * AES-256-GCM authenticated encryption.
 *
 * Used for:
 * - Encrypting secrets with DEK
 * - Wrapping DEK with KEK
 * - Transport encryption (enc_kek)
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits
const TAG_LENGTH = 16; // 128 bits

export const aes256gcm = {
  /**
   * AES_GCM_encrypt(key, plaintext, iv, aad) → { ciphertext, tag, iv }
   * If iv is not provided, a random one is generated.
   */
  encrypt(
    key: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array = new Uint8Array(0),
    iv?: Uint8Array,
  ): { ciphertext: Uint8Array; tag: Uint8Array; iv: Uint8Array } {
    const actualIv = iv ?? randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, key, actualIv, { authTagLength: TAG_LENGTH });
    cipher.setAAD(aad);

    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      ciphertext: new Uint8Array(encrypted),
      tag: new Uint8Array(tag),
      iv: new Uint8Array(actualIv),
    };
  },

  /**
   * AES_GCM_decrypt(key, ciphertext, iv, aad, tag) → plaintext
   * Throws on authentication failure.
   */
  decrypt(
    key: Uint8Array,
    ciphertext: Uint8Array,
    iv: Uint8Array,
    aad: Uint8Array,
    tag: Uint8Array,
  ): Uint8Array {
    const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return new Uint8Array(decrypted);
  },

  /** Generate a random IV (96 bits) */
  generateIv(): Uint8Array {
    return new Uint8Array(randomBytes(IV_LENGTH));
  },
};
