import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { aes256gcm } from '../../src/aes.js';

const key = () => new Uint8Array(randomBytes(32));
const plaintext = () => new TextEncoder().encode('hello clavum');
const aad = () => new TextEncoder().encode('secret-id-123');

describe('aes256gcm', () => {
  it('encrypt/decrypt round-trip', () => {
    const k = key();
    const pt = plaintext();
    const a = aad();
    const { ciphertext, tag, iv } = aes256gcm.encrypt(k, pt, a);
    const decrypted = aes256gcm.decrypt(k, ciphertext, iv, a, tag);
    expect(decrypted).toEqual(pt);
  });

  it('generates random IV when not provided', () => {
    const k = key();
    const pt = plaintext();
    const r1 = aes256gcm.encrypt(k, pt);
    const r2 = aes256gcm.encrypt(k, pt);
    expect(r1.iv.length).toBe(12);
    expect(Buffer.from(r1.iv).equals(Buffer.from(r2.iv))).toBe(false);
  });

  it('decrypt fails with wrong key', () => {
    const k1 = key();
    const k2 = key();
    const a = aad();
    const { ciphertext, tag, iv } = aes256gcm.encrypt(k1, plaintext(), a);
    expect(() => aes256gcm.decrypt(k2, ciphertext, iv, a, tag)).toThrow();
  });

  it('decrypt fails with tampered ciphertext', () => {
    const k = key();
    const a = aad();
    const { ciphertext, tag, iv } = aes256gcm.encrypt(k, plaintext(), a);
    ciphertext[0] ^= 0xff;
    expect(() => aes256gcm.decrypt(k, ciphertext, iv, a, tag)).toThrow();
  });

  it('decrypt fails with wrong AAD', () => {
    const k = key();
    const { ciphertext, tag, iv } = aes256gcm.encrypt(k, plaintext(), aad());
    const wrongAad = new TextEncoder().encode('wrong-id');
    expect(() => aes256gcm.decrypt(k, ciphertext, iv, wrongAad, tag)).toThrow();
  });

  it('decrypt fails with wrong/missing tag', () => {
    const k = key();
    const a = aad();
    const { ciphertext, iv } = aes256gcm.encrypt(k, plaintext(), a);
    const wrongTag = new Uint8Array(16); // all zeros
    expect(() => aes256gcm.decrypt(k, ciphertext, iv, a, wrongTag)).toThrow();
  });
});
