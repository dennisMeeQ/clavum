import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { vault } from '../../src/vault.js';

const testDir = join(tmpdir(), `clavum-vault-test-${Date.now()}`);
let counter = 0;

function freshDbPath(): string {
  counter++;
  return join(testDir, `test-${counter}.db`);
}

beforeAll(() => {
  mkdirSync(testDir, { recursive: true });
});

afterAll(() => {
  rmSync(testDir, { recursive: true, force: true });
});

describe('vault', () => {
  it('initVault creates DB file', () => {
    const dbPath = freshDbPath();
    const db = vault.initVault(dbPath);
    expect(existsSync(dbPath)).toBe(true);
    db.close();
  });

  it('tables created with correct schema', () => {
    const dbPath = freshDbPath();
    const db = vault.initVault(dbPath);

    // Check tables exist by querying sqlite_master
    const stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
    const tables = stmt.all() as { name: string }[];
    const tableNames = tables.map((t) => t.name);
    expect(tableNames).toContain('secrets');
    expect(tableNames).toContain('config');

    db.close();
  });

  it('config get/set round-trip', () => {
    const dbPath = freshDbPath();
    const db = vault.initVault(dbPath);

    vault.setConfig(db, 'server_url', 'https://example.com');
    expect(vault.getConfig(db, 'server_url')).toBe('https://example.com');

    // Overwrite
    vault.setConfig(db, 'server_url', 'https://other.com');
    expect(vault.getConfig(db, 'server_url')).toBe('https://other.com');

    // Missing key
    expect(vault.getConfig(db, 'nonexistent')).toBeUndefined();

    db.close();
  });

  it('initVault is idempotent', () => {
    const dbPath = freshDbPath();
    const db1 = vault.initVault(dbPath);
    vault.setConfig(db1, 'test', 'value');
    db1.close();

    // Second init should not error or lose data
    const db2 = vault.initVault(dbPath);
    expect(vault.getConfig(db2, 'test')).toBe('value');
    db2.close();
  });
});
