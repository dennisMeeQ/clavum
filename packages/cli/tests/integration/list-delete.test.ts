import { randomUUID } from 'node:crypto';
import { existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { deleteSecret, getSecret, initVault, insertSecret, listSecrets } from '../../src/vault.js';

let db: DatabaseSync;
let dbPath: string;

beforeEach(() => {
  dbPath = join(tmpdir(), `clavum-list-del-${randomUUID()}.db`);
  db = initVault(dbPath);
});

afterEach(() => {
  db.close();
  if (existsSync(dbPath)) rmSync(dbPath);
  const walPath = `${dbPath}-wal`;
  const shmPath = `${dbPath}-shm`;
  if (existsSync(walPath)) rmSync(walPath);
  if (existsSync(shmPath)) rmSync(shmPath);
});

describe('list and delete', () => {
  it('should list stored secrets', () => {
    insertSecret(db, { id: randomUUID(), name: 'alpha', tier: 'green' });
    insertSecret(db, { id: randomUUID(), name: 'beta', tier: 'yellow' });

    const secrets = listSecrets(db);
    expect(secrets).toHaveLength(2);
    expect(secrets[0].name).toBe('alpha');
    expect(secrets[1].name).toBe('beta');
  });

  it('should return empty list for empty vault', () => {
    const secrets = listSecrets(db);
    expect(secrets).toHaveLength(0);
  });

  it('should delete from vault', () => {
    insertSecret(db, { id: randomUUID(), name: 'to-delete', tier: 'green' });

    const deleted = deleteSecret(db, 'to-delete');
    expect(deleted).toBe(true);
    expect(getSecret(db, 'to-delete')).toBeNull();
  });

  it('should return false for deleting nonexistent secret', () => {
    const deleted = deleteSecret(db, 'nonexistent');
    expect(deleted).toBe(false);
  });
});
