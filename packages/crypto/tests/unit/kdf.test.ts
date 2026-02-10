import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { kdf } from '../../src/kdf.js';

describe('kdf', () => {
  describe('deriveKek', () => {
    const ikm = new Uint8Array(randomBytes(32));
    const salt = new Uint8Array(randomBytes(16));
    const secretId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

    it('same inputs produce same KEK', () => {
      const kek1 = kdf.deriveKek(ikm, salt, secretId);
      const kek2 = kdf.deriveKek(ikm, salt, secretId);
      expect(kek1.length).toBe(32);
      expect(Buffer.from(kek1).equals(Buffer.from(kek2))).toBe(true);
    });

    it('different salt produces different KEK', () => {
      const salt2 = new Uint8Array(randomBytes(16));
      const kek1 = kdf.deriveKek(ikm, salt, secretId);
      const kek2 = kdf.deriveKek(ikm, salt2, secretId);
      expect(Buffer.from(kek1).equals(Buffer.from(kek2))).toBe(false);
    });

    it('different secretId produces different KEK', () => {
      const kek1 = kdf.deriveKek(ikm, salt, secretId);
      const kek2 = kdf.deriveKek(ikm, salt, 'ffffffff-ffff-ffff-ffff-ffffffffffff');
      expect(Buffer.from(kek1).equals(Buffer.from(kek2))).toBe(false);
    });
  });

  describe('deriveFingerprint', () => {
    it('produces 4 bytes', () => {
      const fp = kdf.deriveFingerprint(new Uint8Array(randomBytes(32)));
      expect(fp.length).toBe(4);
    });

    it('is deterministic', () => {
      const secret = new Uint8Array(randomBytes(32));
      const fp1 = kdf.deriveFingerprint(secret);
      const fp2 = kdf.deriveFingerprint(secret);
      expect(Buffer.from(fp1).equals(Buffer.from(fp2))).toBe(true);
    });
  });

  describe('hmac', () => {
    it('produces 32 bytes', () => {
      const result = kdf.hmac(new Uint8Array(32), new Uint8Array([1, 2, 3]));
      expect(result.length).toBe(32);
    });

    it('is deterministic', () => {
      const key = new Uint8Array(randomBytes(32));
      const msg = new TextEncoder().encode('test');
      const h1 = kdf.hmac(key, msg);
      const h2 = kdf.hmac(key, msg);
      expect(Buffer.from(h1).equals(Buffer.from(h2))).toBe(true);
    });
  });

  describe('hash', () => {
    it('known SHA-256 test vector', () => {
      // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const result = kdf.hash(new Uint8Array(0));
      expect(Buffer.from(result).toString('hex')).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });
  });
});
