import { describe, expect, it } from 'vitest';
import { ed25519, x25519 } from '../../src/keys.js';

describe('x25519', () => {
  describe('generateKeypair', () => {
    it('produces 32-byte keys', () => {
      const { privateKey, publicKey } = x25519.generateKeypair();
      expect(privateKey.length).toBe(32);
      expect(publicKey.length).toBe(32);
    });

    it('produces different keypairs each time', () => {
      const a = x25519.generateKeypair();
      const b = x25519.generateKeypair();
      expect(Buffer.from(a.privateKey).equals(Buffer.from(b.privateKey))).toBe(false);
    });
  });

  describe('sharedSecret', () => {
    it('both parties derive the same shared secret', () => {
      const alice = x25519.generateKeypair();
      const bob = x25519.generateKeypair();
      const secretAB = x25519.sharedSecret(alice.privateKey, bob.publicKey);
      const secretBA = x25519.sharedSecret(bob.privateKey, alice.publicKey);
      expect(secretAB.length).toBe(32);
      expect(Buffer.from(secretAB).equals(Buffer.from(secretBA))).toBe(true);
    });

    it('different keypairs produce different secrets', () => {
      const alice = x25519.generateKeypair();
      const bob = x25519.generateKeypair();
      const eve = x25519.generateKeypair();
      const secretAB = x25519.sharedSecret(alice.privateKey, bob.publicKey);
      const secretAE = x25519.sharedSecret(alice.privateKey, eve.publicKey);
      expect(Buffer.from(secretAB).equals(Buffer.from(secretAE))).toBe(false);
    });

    it('RFC 7748 Section 6.1 test vector', () => {
      // Alice's private key (scalar)
      const alicePriv = new Uint8Array(
        Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex'),
      );
      // Alice's public key
      const alicePub = new Uint8Array(
        Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex'),
      );
      // Bob's private key (scalar)
      const bobPriv = new Uint8Array(
        Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex'),
      );
      // Bob's public key
      const bobPub = new Uint8Array(
        Buffer.from('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex'),
      );
      // Expected shared secret
      const expected = new Uint8Array(
        Buffer.from('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742', 'hex'),
      );

      const secretAB = x25519.sharedSecret(alicePriv, bobPub);
      const secretBA = x25519.sharedSecret(bobPriv, alicePub);
      expect(Buffer.from(secretAB).toString('hex')).toBe(Buffer.from(expected).toString('hex'));
      expect(Buffer.from(secretBA).toString('hex')).toBe(Buffer.from(expected).toString('hex'));
    });
  });
});

describe('ed25519', () => {
  describe('generateKeypair', () => {
    it('produces 32-byte keys', () => {
      const { privateKey, publicKey } = ed25519.generateKeypair();
      expect(privateKey.length).toBe(32);
      expect(publicKey.length).toBe(32);
    });
  });

  describe('sign / verify', () => {
    it('round-trips correctly', () => {
      const { privateKey, publicKey } = ed25519.generateKeypair();
      const message = new TextEncoder().encode('hello world');
      const sig = ed25519.sign(privateKey, message);
      expect(sig.length).toBe(64);
      expect(ed25519.verify(publicKey, message, sig)).toBe(true);
    });

    it('rejects wrong message', () => {
      const { privateKey, publicKey } = ed25519.generateKeypair();
      const sig = ed25519.sign(privateKey, new TextEncoder().encode('hello'));
      expect(ed25519.verify(publicKey, new TextEncoder().encode('world'), sig)).toBe(false);
    });

    it('rejects wrong public key', () => {
      const alice = ed25519.generateKeypair();
      const bob = ed25519.generateKeypair();
      const message = new TextEncoder().encode('test');
      const sig = ed25519.sign(alice.privateKey, message);
      expect(ed25519.verify(bob.publicKey, message, sig)).toBe(false);
    });

    it('rejects tampered signature', () => {
      const { privateKey, publicKey } = ed25519.generateKeypair();
      const message = new TextEncoder().encode('test');
      const sig = ed25519.sign(privateKey, message);
      sig[0] ^= 0xff; // tamper
      expect(ed25519.verify(publicKey, message, sig)).toBe(false);
    });

    it('sign produces deterministic 64-byte signatures', () => {
      const { privateKey } = ed25519.generateKeypair();
      const message = new TextEncoder().encode('deterministic');
      const sig1 = ed25519.sign(privateKey, message);
      const sig2 = ed25519.sign(privateKey, message);
      expect(sig1.length).toBe(64);
      expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(true);
    });

    it('empty message round-trip', () => {
      const { privateKey, publicKey } = ed25519.generateKeypair();
      const message = new Uint8Array(0);
      const sig = ed25519.sign(privateKey, message);
      expect(ed25519.verify(publicKey, message, sig)).toBe(true);
    });
  });
});
