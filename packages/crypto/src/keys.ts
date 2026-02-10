/**
 * Key generation and ECDH operations.
 *
 * X25519 — ECDH key agreement (RFC 7748)
 * Ed25519 — Digital signatures (RFC 8032)
 */

import { ed25519 as ed25519curve, x25519 as x25519curve } from '@noble/curves/ed25519';

export const x25519 = {
  /** Generate a new X25519 keypair */
  generateKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const privateKey = x25519curve.utils.randomPrivateKey();
    const publicKey = x25519curve.getPublicKey(privateKey);
    return { privateKey, publicKey };
  },

  /** Derive shared secret: X25519(privateKey, publicKey) → 32 bytes */
  sharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    return x25519curve.getSharedSecret(privateKey, publicKey);
  },

  /** Get public key from private key */
  getPublicKey(privateKey: Uint8Array): Uint8Array {
    return x25519curve.getPublicKey(privateKey);
  },
};

export const ed25519 = {
  /** Generate a new Ed25519 keypair */
  generateKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const privateKey = ed25519curve.utils.randomPrivateKey();
    const publicKey = ed25519curve.getPublicKey(privateKey);
    return { privateKey, publicKey };
  },

  /** Sign a message: Ed25519_sign(privateKey, message) → 64 bytes */
  sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
    return ed25519curve.sign(message, privateKey);
  },

  /** Verify a signature: Ed25519_verify(publicKey, message, signature) → bool */
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    return ed25519curve.verify(signature, message, publicKey);
  },

  /** Get public key from private key */
  getPublicKey(privateKey: Uint8Array): Uint8Array {
    return ed25519curve.getPublicKey(privateKey);
  },
};
