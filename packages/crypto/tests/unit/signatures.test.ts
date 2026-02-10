import { describe, expect, it } from 'vitest';
import { ed25519 } from '../../src/keys.js';
import { signatures } from '../../src/signatures.js';

describe('signatures', () => {
  const keypair = ed25519.generateKeypair();

  describe('signRequest / verifyRequest', () => {
    it('round-trips correctly', () => {
      const timestamp = Date.now().toString();
      const method = 'POST';
      const path = '/api/secrets';
      const body = new TextEncoder().encode('{"data":"test"}');

      const sig = signatures.signRequest(keypair.privateKey, timestamp, method, path, body);
      expect(sig.length).toBe(64);
      expect(signatures.verifyRequest(keypair.publicKey, timestamp, method, path, body, sig)).toBe(
        true,
      );
    });

    it('rejects expired timestamp', () => {
      const oldTimestamp = (Date.now() - 120_000).toString(); // 2 min ago
      const body = new Uint8Array(0);
      const sig = signatures.signRequest(keypair.privateKey, oldTimestamp, 'GET', '/test', body);
      expect(
        signatures.verifyRequest(keypair.publicKey, oldTimestamp, 'GET', '/test', body, sig),
      ).toBe(false);
    });

    it('rejects wrong body', () => {
      const ts = Date.now().toString();
      const sig = signatures.signRequest(
        keypair.privateKey,
        ts,
        'POST',
        '/api',
        new TextEncoder().encode('original'),
      );
      expect(
        signatures.verifyRequest(
          keypair.publicKey,
          ts,
          'POST',
          '/api',
          new TextEncoder().encode('tampered'),
          sig,
        ),
      ).toBe(false);
    });

    it('rejects wrong method', () => {
      const ts = Date.now().toString();
      const body = new Uint8Array(0);
      const sig = signatures.signRequest(keypair.privateKey, ts, 'POST', '/api', body);
      expect(signatures.verifyRequest(keypair.publicKey, ts, 'GET', '/api', body, sig)).toBe(false);
    });

    it('rejects wrong path', () => {
      const ts = Date.now().toString();
      const body = new Uint8Array(0);
      const sig = signatures.signRequest(keypair.privateKey, ts, 'GET', '/api/a', body);
      expect(signatures.verifyRequest(keypair.publicKey, ts, 'GET', '/api/b', body, sig)).toBe(
        false,
      );
    });
  });

  describe('buildChallenge', () => {
    it('contains nonce + secretId + reasonHash', () => {
      const nonce = new Uint8Array(32).fill(0xab);
      const secretId = 'test-id';
      const challenge = signatures.buildChallenge(secretId, 'read access', nonce);
      // 32 (nonce) + 7 (secretId bytes) + 32 (reasonHash) = 71
      expect(challenge.length).toBe(71);
      // First 32 bytes should be the nonce
      expect(Buffer.from(challenge.subarray(0, 32)).equals(Buffer.from(nonce))).toBe(true);
    });

    it('different nonces produce different challenges', () => {
      const c1 = signatures.buildChallenge('id', 'reason');
      const c2 = signatures.buildChallenge('id', 'reason');
      // Random nonces → different challenges
      expect(Buffer.from(c1).equals(Buffer.from(c2))).toBe(false);
    });
  });

  describe('signApproval / verifyApproval', () => {
    it('round-trips correctly', () => {
      const challenge = signatures.buildChallenge('secret-1', 'approve');
      const sig = signatures.signApproval(keypair.privateKey, challenge);
      expect(signatures.verifyApproval(keypair.publicKey, challenge, sig)).toBe(true);
    });

    it('rejects wrong challenge', () => {
      const c1 = signatures.buildChallenge('secret-1', 'approve');
      const c2 = signatures.buildChallenge('secret-2', 'approve');
      const sig = signatures.signApproval(keypair.privateKey, c1);
      expect(signatures.verifyApproval(keypair.publicKey, c2, sig)).toBe(false);
    });
  });
});
