import { existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

// Mock homedir to use temp directory
const testDir = join(tmpdir(), `clavum-test-${Date.now()}`);
vi.mock('node:os', async () => {
  const actual = await vi.importActual<typeof import('node:os')>('node:os');
  return { ...actual, homedir: () => testDir };
});

// Import after mock
const { keystore } = await import('../../src/keystore.js');

beforeAll(() => {
  mkdirSync(testDir, { recursive: true });
});

afterAll(() => {
  rmSync(testDir, { recursive: true, force: true });
});

describe('keystore', () => {
  it('store and load round-trip', () => {
    const key = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    keystore.store('test-key', key);
    const loaded = keystore.load('test-key');
    expect(loaded).toEqual(key);
  });

  it('file has correct permissions (600)', () => {
    keystore.store('perm-test', new Uint8Array(32));
    const filePath = join(testDir, '.clavum', 'perm-test.key');
    const stat = statSync(filePath);
    // Check owner-only read/write (0o600 = 384 decimal)
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('exists returns true for stored key', () => {
    keystore.store('exists-test', new Uint8Array(16));
    expect(keystore.exists('exists-test')).toBe(true);
  });

  it('exists returns false for missing key', () => {
    expect(keystore.exists('nonexistent')).toBe(false);
  });

  it('load returns null for missing key', () => {
    expect(keystore.load('nonexistent')).toBeNull();
  });
});
