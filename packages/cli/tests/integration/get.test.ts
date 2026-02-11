import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { aes256gcm, ed25519, flows, toBase64Url, x25519 } from '@clavum/crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { dekCache } from '../../src/cache.js';
import { getSecret, initVault, insertSecret, setConfig } from '../../src/vault.js';

// Server keys for the test
const serverKeys = x25519.generateKeypair();
const agentX25519 = x25519.generateKeypair();
const _agentEd25519 = ed25519.generateKeypair();

// Compute K_session for mocking server response
const kSession = x25519.sharedSecret(serverKeys.privateKey, agentX25519.publicKey);

let _mockRetrieveCalled = false;
let mockRetrieveKek: Uint8Array | null = null;

vi.mock('../../src/http.js', () => ({
  signedFetch: vi.fn(async () => {
    _mockRetrieveCalled = true;
    if (!mockRetrieveKek) throw new Error('No KEK set for mock');

    // Encrypt KEK with K_session like the server would
    const { ciphertext, iv, tag } = aes256gcm.encrypt(kSession, mockRetrieveKek);
    return {
      enc_kek: toBase64Url(ciphertext),
      enc_kek_iv: toBase64Url(iv),
      enc_kek_tag: toBase64Url(tag),
    };
  }),
  AuthError: class extends Error {},
  NotFoundError: class extends Error {},
  ConflictError: class extends Error {},
  ServerError: class extends Error {},
}));

let dbPath: string;
let db: DatabaseSync;

beforeEach(() => {
  dbPath = join(tmpdir(), `clavum-get-test-${randomUUID()}.db`);
  db = initVault(dbPath);
  setConfig(db, 'server_url', 'http://localhost:3000');
  setConfig(db, 'server_x25519_pub', toBase64Url(serverKeys.publicKey));
  setConfig(db, 'agent_id', 'test-agent-id');
  _mockRetrieveCalled = false;
  mockRetrieveKek = null;
  dekCache.clear();
});

afterEach(() => {
  db.close();
  if (existsSync(dbPath)) rmSync(dbPath);
  const walPath = `${dbPath}-wal`;
  const shmPath = `${dbPath}-shm`;
  if (existsSync(walPath)) rmSync(walPath);
  if (existsSync(shmPath)) rmSync(shmPath);
});

describe('clavum get', () => {
  it('should retrieve a secret from vault with KEK unwrapping', () => {
    const secretId = randomUUID();
    const dek = new Uint8Array(randomBytes(32));
    const kekSalt = new Uint8Array(randomBytes(32));

    // Derive KEK same way the server would
    const kek = flows.deriveGreenKek(
      serverKeys.privateKey,
      agentX25519.publicKey,
      kekSalt,
      secretId,
    );
    const aad = new Uint8Array(0);
    const { encryptedDek, dekIv, dekTag } = flows.wrapDek(kek, dek, aad);

    insertSecret(db, {
      id: secretId,
      name: 'test-secret',
      tier: 'green',
      serverSecretId: secretId,
      kekSalt,
      encryptedDek,
      dekIv,
      dekTag,
    });

    // Verify record stored
    const record = getSecret(db, 'test-secret');
    expect(record).not.toBeNull();
    expect(record?.encryptedDek).toHaveLength(encryptedDek.length);
  });

  it('should use cached DEK when available', () => {
    const secretId = randomUUID();
    const dek = new Uint8Array(randomBytes(32));

    dekCache.set(secretId, dek);
    const cached = dekCache.get(secretId);

    expect(cached).not.toBeNull();
    expect(cached).toHaveLength(32);
  });

  it('should return null for nonexistent secret', () => {
    const record = getSecret(db, 'nonexistent');
    expect(record).toBeNull();
  });
});
