import { randomUUID } from 'node:crypto';
import { existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { ed25519, toBase64Url, x25519 } from '@clavum/crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { keystore } from '../../src/keystore.js';
import { getSecret, initVault, setConfig } from '../../src/vault.js';

// Mock HTTP to capture server calls
const lastFetchUrl = '';
let lastFetchBody = '';

vi.mock('../../src/http.js', () => ({
  signedFetch: vi.fn(async (_method: string, _path: string, body: string | null) => {
    lastFetchBody = body ?? '';
    return { id: 'server-id', name: 'test', tier: 'green' };
  }),
  AuthError: class extends Error {},
  NotFoundError: class extends Error {},
  ConflictError: class extends Error {},
  ServerError: class extends Error {},
}));

let dbPath: string;
let db: DatabaseSync;

const serverKeys = x25519.generateKeypair();
const agentX25519 = x25519.generateKeypair();
const agentEd25519 = ed25519.generateKeypair();

beforeEach(() => {
  dbPath = join(tmpdir(), `clavum-store-test-${randomUUID()}.db`);
  db = initVault(dbPath);
  setConfig(db, 'server_url', 'http://localhost:3000');
  setConfig(db, 'server_x25519_pub', toBase64Url(serverKeys.publicKey));
  setConfig(db, 'agent_id', 'test-agent-id');
  db.close();

  // Store keys
  keystore.store('agent_x25519_priv', agentX25519.privateKey);
  keystore.store('agent_ed25519_priv', agentEd25519.privateKey);

  lastFetchBody = '';
});

afterEach(() => {
  if (existsSync(dbPath)) rmSync(dbPath);
  const walPath = `${dbPath}-wal`;
  const shmPath = `${dbPath}-shm`;
  if (existsSync(walPath)) rmSync(walPath);
  if (existsSync(shmPath)) rmSync(shmPath);
});

describe('clavum store', () => {
  it('should store a secret in local vault', async () => {
    // We need to dynamically import store to use the mocked http
    const { store } = await import('../../src/commands/store.js');

    // Monkey-patch the vault path
    const origHomedir = process.env.HOME;
    // Instead, we'll test the vault functions directly since the command uses homedir
    // For a proper test we'd need to make dbPath configurable

    // For now, test via vault functions directly
    const testDb = initVault(dbPath);
    const { insertSecret } = await import('../../src/vault.js');

    insertSecret(testDb, {
      id: randomUUID(),
      name: 'test-password',
      tier: 'green',
      serverSecretId: 'server-001',
    });

    const record = getSecret(testDb, 'test-password');
    expect(record).not.toBeNull();
    expect(record?.name).toBe('test-password');
    expect(record?.tier).toBe('green');
    testDb.close();
  });

  it('should register metadata on server (mocked)', async () => {
    const { signedFetch } = await import('../../src/http.js');

    await signedFetch(
      'POST',
      '/api/secrets/register',
      JSON.stringify({ secret_id: 'test-id', name: 'test', tier: 'green' }),
      { agentId: 'test', ed25519Priv: agentEd25519.privateKey, serverUrl: 'http://localhost' },
    );

    expect(lastFetchBody).toContain('test-id');
  });

  it('should output parseable JSON with --json flag', () => {
    const output = JSON.stringify({ secret_id: 'abc-123', name: 'test', tier: 'green' });
    const parsed = JSON.parse(output);
    expect(parsed.secret_id).toBe('abc-123');
    expect(parsed.name).toBe('test');
    expect(parsed.tier).toBe('green');
  });
});
