/**
 * Key generation and ECDH operations.
 *
 * X25519 — ECDH key agreement (RFC 7748)
 * Ed25519 — Digital signatures (RFC 8032)
 *
 * Uses Node.js built-in crypto only.
 */

import {
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';

export const x25519 = {
  /** Generate a new X25519 keypair. Returns raw 32-byte keys. */
  generateKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const { publicKey, privateKey } = generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
    // Extract raw 32-byte keys from DER encoding
    // X25519 SPKI DER: 12-byte header + 32-byte key
    // X25519 PKCS8 DER: 16-byte header + 32-byte key
    return {
      publicKey: new Uint8Array(publicKey.subarray(publicKey.length - 32)),
      privateKey: new Uint8Array(privateKey.subarray(privateKey.length - 32)),
    };
  },

  /** Derive shared secret: X25519(privateKey, publicKey) → 32 bytes */
  sharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    const privKeyObj = createPrivateKey({
      key: Buffer.concat([
        // PKCS8 DER header for X25519
        Buffer.from('302e020100300506032b656e04220420', 'hex'),
        privateKey,
      ]),
      format: 'der',
      type: 'pkcs8',
    });
    const pubKeyObj = createPublicKey({
      key: Buffer.concat([
        // SPKI DER header for X25519
        Buffer.from('302a300506032b656e032100', 'hex'),
        publicKey,
      ]),
      format: 'der',
      type: 'spki',
    });
    const shared = diffieHellman({ privateKey: privKeyObj, publicKey: pubKeyObj });
    return new Uint8Array(shared);
  },
};

export const ed25519 = {
  /** Generate a new Ed25519 keypair. Returns raw 32-byte keys. */
  generateKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
    // Ed25519 SPKI DER: 12-byte header + 32-byte key
    // Ed25519 PKCS8 DER: 16-byte header + 32-byte key
    return {
      publicKey: new Uint8Array(publicKey.subarray(publicKey.length - 32)),
      privateKey: new Uint8Array(privateKey.subarray(privateKey.length - 32)),
    };
  },

  /** Sign a message: Ed25519_sign(privateKey, message) → 64 bytes */
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
    const privKeyObj = createPrivateKey({
      key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), privateKey]),
      format: 'der',
      type: 'pkcs8',
    });
    const signature = sign(null, message, privKeyObj);
    return new Uint8Array(signature);
  },

  /** Verify a signature: Ed25519_verify(publicKey, message, signature) → bool */
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    const pubKeyObj = createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publicKey]),
      format: 'der',
      type: 'spki',
    });
    return verify(null, message, pubKeyObj, signature);
  },
};
