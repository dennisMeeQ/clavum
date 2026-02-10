import { existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ed25519, fingerprintToEmoji, kdf, toBase64Url, x25519 } from '@clavum/crypto';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// Mock the homedir so we don't touch real ~/.clavum
const testDir = join(tmpdir(), `clavum-test-${Date.now()}`);
vi.mock('node:os', async (importOriginal) => {
  const orig = (await importOriginal()) as typeof import('node:os');
  return { ...orig, homedir: () => testDir };
});

// Import after mocking
const { pair } = await import('../../src/commands/pair.js');
const { keystore } = await import('../../src/keystore.js');
const { initVault, getConfig } = await import('../../src/vault.js');

// Server keypair for mocking
const serverKeys = x25519.generateKeypair();

function mockFetch(agentPubB64url: string) {
  const agentPub = new Uint8Array(Buffer.from(agentPubB64url, 'base64url'));
  const sharedSecret = x25519.sharedSecret(serverKeys.privateKey, agentPub);
  const fpBytes = kdf.deriveFingerprint(sharedSecret);
  const fingerprint = fingerprintToEmoji(fpBytes);

  return {
    agentId: 'test-agent-id',
    serverX25519Pub: toBase64Url(serverKeys.publicKey),
    fingerprint,
  };
}

beforeAll(() => {
  mkdirSync(testDir, { recursive: true });
});

afterAll(() => {
  rmSync(testDir, { recursive: true, force: true });
});

beforeEach(() => {
  // Clear .clavum dir
  const clavumDir = join(testDir, '.clavum');
  if (existsSync(clavumDir)) {
    rmSync(clavumDir, { recursive: true });
  }
});

describe('clavum pair', () => {
  it('full pair flow with mocked HTTP', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const body = JSON.parse((init?.body as string) || '{}');
      const data = mockFetch(body.x25519_pub);
      return new Response(JSON.stringify(data), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    await pair({
      serverUrl: 'http://localhost:3000',
      token: 'test-token',
      name: 'test-agent',
    });

    // Verify keys were stored
    expect(keystore.exists('agent_x25519')).toBe(true);
    expect(keystore.exists('agent_ed25519')).toBe(true);

    // Verify key file permissions
    const x25519Path = join(testDir, '.clavum', 'agent_x25519.key');
    const stat = statSync(x25519Path);
    expect(stat.mode & 0o777).toBe(0o600);

    // Verify vault config
    const vaultPath = join(testDir, '.clavum', 'vault.db');
    expect(existsSync(vaultPath)).toBe(true);
    const db = initVault(vaultPath);
    expect(getConfig(db, 'server_url')).toBe('http://localhost:3000');
    expect(getConfig(db, 'agent_id')).toBe('test-agent-id');
    expect(getConfig(db, 'server_x25519_pub')).toBe(toBase64Url(serverKeys.publicKey));
    db.close();

    fetchSpy.mockRestore();
  });

  it('server error gives clean error message', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      return new Response(JSON.stringify({ error: 'token expired' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    await expect(
      pair({
        serverUrl: 'http://localhost:3000',
        token: 'bad-token',
      }),
    ).rejects.toThrow('Pairing failed (400): token expired');

    fetchSpy.mockRestore();
  });

  it('already paired warns but continues', async () => {
    // Store a dummy key first
    keystore.store('agent_x25519', new Uint8Array(32));

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const body = JSON.parse((init?.body as string) || '{}');
      const data = mockFetch(body.x25519_pub);
      return new Response(JSON.stringify(data), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    await pair({
      serverUrl: 'http://localhost:3000',
      token: 'test-token',
    });

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('Already paired'));

    warnSpy.mockRestore();
    fetchSpy.mockRestore();
  });
});
