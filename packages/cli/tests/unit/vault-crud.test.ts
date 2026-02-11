import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  deleteSecret,
  getSecret,
  getSecretById,
  initVault,
  insertSecret,
  listSecrets,
} from '../../src/vault.js';

let db: DatabaseSync;
let dbPath: string;

beforeEach(() => {
  dbPath = join(tmpdir(), `clavum-vault-crud-${randomUUID()}.db`);
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

describe('vault CRUD', () => {
  it('should insert and get a secret by name', () => {
    const id = randomUUID();
    insertSecret(db, {
      id,
      name: 'db-password',
      tier: 'green',
      serverSecretId: 'server-001',
      kekSalt: new Uint8Array(randomBytes(32)),
      encryptedDek: new Uint8Array(randomBytes(48)),
      dekIv: new Uint8Array(randomBytes(12)),
      dekTag: new Uint8Array(randomBytes(16)),
    });

    const record = getSecret(db, 'db-password');
    expect(record).not.toBeNull();
    expect(record?.id).toBe(id);
    expect(record?.name).toBe('db-password');
    expect(record?.tier).toBe('green');
    expect(record?.kekSalt).toHaveLength(32);
    expect(record?.encryptedDek).toHaveLength(48);
  });

  it('should get a secret by ID', () => {
    const id = randomUUID();
    insertSecret(db, { id, name: 'by-id-test', tier: 'green' });

    const record = getSecretById(db, id);
    expect(record).not.toBeNull();
    expect(record?.name).toBe('by-id-test');
  });

  it('should list all secrets', () => {
    insertSecret(db, { id: randomUUID(), name: 'alpha', tier: 'green' });
    insertSecret(db, { id: randomUUID(), name: 'beta', tier: 'yellow' });
    insertSecret(db, { id: randomUUID(), name: 'gamma', tier: 'red' });

    const list = listSecrets(db);
    expect(list).toHaveLength(3);
    expect(list[0].name).toBe('alpha');
    expect(list[1].name).toBe('beta');
    expect(list[2].name).toBe('gamma');
  });

  it('should delete a secret', () => {
    insertSecret(db, { id: randomUUID(), name: 'to-delete', tier: 'green' });

    const deleted = deleteSecret(db, 'to-delete');
    expect(deleted).toBe(true);

    const record = getSecret(db, 'to-delete');
    expect(record).toBeNull();
  });

  it('should return null for nonexistent secret', () => {
    expect(getSecret(db, 'nonexistent')).toBeNull();
    expect(getSecretById(db, randomUUID())).toBeNull();
  });

  it('should throw on duplicate name', () => {
    insertSecret(db, { id: randomUUID(), name: 'unique-name', tier: 'green' });
    expect(() => {
      insertSecret(db, { id: randomUUID(), name: 'unique-name', tier: 'green' });
    }).toThrow();
  });
});
