import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { flows } from '../../src/flows.js';
import { kdf } from '../../src/kdf.js';
import { x25519 } from '../../src/keys.js';
import { signatures } from '../../src/signatures.js';

const secretId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const kekSalt = new Uint8Array(randomBytes(16));
const dek = new Uint8Array(randomBytes(32));
const plaintext = new TextEncoder().encode('super secret password');
const aad = new TextEncoder().encode(secretId);

describe('flows', () => {
  describe('deriveGreenKek', () => {
    it('agent ephemeral and server derive same KEK', () => {
      const agent = x25519.generateKeypair();
      const server = x25519.generateKeypair();

      // Agent side: uses agent ephemeral private + server public
      const kekAgent = flows.deriveGreenKek(agent.privateKey, server.publicKey, kekSalt, secretId);

      // Server side: uses server private + agent ephemeral public → same shared secret
      const sharedServer = x25519.sharedSecret(server.privateKey, agent.publicKey);
      const kekServer = kdf.deriveKek(sharedServer, kekSalt, secretId);

      expect(kekAgent.length).toBe(32);
      expect(Buffer.from(kekAgent).equals(Buffer.from(kekServer))).toBe(true);
    });
  });

  describe('green full round-trip', () => {
    it('encrypt → wrap → unwrap → decrypt', () => {
      const agent = x25519.generateKeypair();
      const server = x25519.generateKeypair();

      const kek = flows.deriveGreenKek(agent.privateKey, server.publicKey, kekSalt, secretId);

      // Encrypt secret with DEK
      const { encryptedBlob, blobIv, blobTag } = flows.encryptSecret(dek, plaintext, aad);

      // Wrap DEK with KEK
      const { encryptedDek, dekIv, dekTag } = flows.wrapDek(kek, dek, aad);

      // Server side: derive same KEK, unwrap DEK, decrypt secret
      const kekServer = flows.deriveGreenKek(server.privateKey, agent.publicKey, kekSalt, secretId);
      const recoveredDek = flows.unwrapDek(kekServer, encryptedDek, dekIv, aad, dekTag);
      const recovered = flows.decryptSecret(recoveredDek, encryptedBlob, blobIv, aad, blobTag);

      expect(recovered).toEqual(plaintext);
    });
  });

  describe('deriveRedKek', () => {
    it('derived from K_agent ‖ K_phone + challenge', () => {
      const kAgent = new Uint8Array(randomBytes(32));
      const kPhone = new Uint8Array(randomBytes(32));
      const challenge = signatures.buildChallenge(secretId, 'read');

      const kek = flows.deriveRedKek(kAgent, kPhone, challenge, secretId);
      expect(kek.length).toBe(32);
    });

    it('different challenge produces different KEK', () => {
      const kAgent = new Uint8Array(randomBytes(32));
      const kPhone = new Uint8Array(randomBytes(32));
      const c1 = signatures.buildChallenge(secretId, 'read');
      const c2 = signatures.buildChallenge(secretId, 'read'); // different nonce

      const kek1 = flows.deriveRedKek(kAgent, kPhone, c1, secretId);
      const kek2 = flows.deriveRedKek(kAgent, kPhone, c2, secretId);
      expect(Buffer.from(kek1).equals(Buffer.from(kek2))).toBe(false);
    });
  });

  describe('wrapDek / unwrapDek', () => {
    it('round-trips correctly', () => {
      const kek = new Uint8Array(randomBytes(32));
      const { encryptedDek, dekIv, dekTag } = flows.wrapDek(kek, dek, aad);
      const recovered = flows.unwrapDek(kek, encryptedDek, dekIv, aad, dekTag);
      expect(recovered).toEqual(dek);
    });

    it('fails with wrong KEK', () => {
      const kek1 = new Uint8Array(randomBytes(32));
      const kek2 = new Uint8Array(randomBytes(32));
      const { encryptedDek, dekIv, dekTag } = flows.wrapDek(kek1, dek, aad);
      expect(() => flows.unwrapDek(kek2, encryptedDek, dekIv, aad, dekTag)).toThrow();
    });
  });

  describe('encryptSecret / decryptSecret', () => {
    it('round-trips correctly', () => {
      const { encryptedBlob, blobIv, blobTag } = flows.encryptSecret(dek, plaintext, aad);
      const recovered = flows.decryptSecret(dek, encryptedBlob, blobIv, aad, blobTag);
      expect(recovered).toEqual(plaintext);
    });

    it('fails with wrong DEK', () => {
      const wrongDek = new Uint8Array(randomBytes(32));
      const { encryptedBlob, blobIv, blobTag } = flows.encryptSecret(dek, plaintext, aad);
      expect(() => flows.decryptSecret(wrongDek, encryptedBlob, blobIv, aad, blobTag)).toThrow();
    });
  });
});
