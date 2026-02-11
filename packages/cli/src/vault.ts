/**
 * Local vault for Clavum CLI.
 *
 * SQLite database storing secret metadata and config.
 * Uses Node.js built-in SQLite (node:sqlite, available since Node 22.5).
 */

import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  tier TEXT NOT NULL CHECK (tier IN ('green', 'yellow', 'red')),
  server_secret_id TEXT,
  kek_salt BLOB,
  encrypted_dek BLOB,
  dek_iv BLOB,
  dek_tag BLOB,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

/**
 * Initialize the vault database. Creates tables if they don't exist.
 * Idempotent — safe to call multiple times.
 */
export function initVault(dbPath: string): DatabaseSync {
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec(SCHEMA);
  return db;
}

/**
 * Get a config value.
 */
export function getConfig(db: DatabaseSync, key: string): string | undefined {
  const stmt = db.prepare('SELECT value FROM config WHERE key = ?');
  const row = stmt.get(key) as { value: string } | undefined;
  return row?.value;
}

/**
 * Set a config value (upsert).
 */
export function setConfig(db: DatabaseSync, key: string, value: string): void {
  const stmt = db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)');
  stmt.run(key, value);
}

export interface VaultRecord {
  id: string;
  name: string;
  tier: string;
  serverSecretId: string | null;
  kekSalt: Uint8Array | null;
  encryptedDek: Uint8Array | null;
  dekIv: Uint8Array | null;
  dekTag: Uint8Array | null;
  createdAt: string;
  updatedAt: string;
}

interface RawRow {
  id: string;
  name: string;
  tier: string;
  server_secret_id: string | null;
  kek_salt: Buffer | null;
  encrypted_dek: Buffer | null;
  dek_iv: Buffer | null;
  dek_tag: Buffer | null;
  created_at: string;
  updated_at: string;
}

function rowToRecord(row: RawRow): VaultRecord {
  return {
    id: row.id,
    name: row.name,
    tier: row.tier,
    serverSecretId: row.server_secret_id,
    kekSalt: row.kek_salt ? new Uint8Array(row.kek_salt) : null,
    encryptedDek: row.encrypted_dek ? new Uint8Array(row.encrypted_dek) : null,
    dekIv: row.dek_iv ? new Uint8Array(row.dek_iv) : null,
    dekTag: row.dek_tag ? new Uint8Array(row.dek_tag) : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Insert a secret record into the vault.
 */
export function insertSecret(
  db: DatabaseSync,
  record: {
    id: string;
    name: string;
    tier: string;
    serverSecretId?: string;
    kekSalt?: Uint8Array;
    encryptedDek?: Uint8Array;
    dekIv?: Uint8Array;
    dekTag?: Uint8Array;
  },
): void {
  const stmt = db.prepare(
    `INSERT INTO secrets (id, name, tier, server_secret_id, kek_salt, encrypted_dek, dek_iv, dek_tag)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  stmt.run(
    record.id,
    record.name,
    record.tier,
    record.serverSecretId ?? null,
    record.kekSalt ? Buffer.from(record.kekSalt) : null,
    record.encryptedDek ? Buffer.from(record.encryptedDek) : null,
    record.dekIv ? Buffer.from(record.dekIv) : null,
    record.dekTag ? Buffer.from(record.dekTag) : null,
  );
}

/**
 * Get a secret by name.
 */
export function getSecret(db: DatabaseSync, name: string): VaultRecord | null {
  const stmt = db.prepare('SELECT * FROM secrets WHERE name = ?');
  const row = stmt.get(name) as RawRow | undefined;
  return row ? rowToRecord(row) : null;
}

/**
 * Get a secret by ID.
 */
export function getSecretById(db: DatabaseSync, id: string): VaultRecord | null {
  const stmt = db.prepare('SELECT * FROM secrets WHERE id = ?');
  const row = stmt.get(id) as RawRow | undefined;
  return row ? rowToRecord(row) : null;
}

/**
 * List all secrets (summary).
 */
export function listSecrets(db: DatabaseSync): { name: string; tier: string; createdAt: string }[] {
  const stmt = db.prepare('SELECT name, tier, created_at FROM secrets ORDER BY name');
  const rows = stmt.all() as { name: string; tier: string; created_at: string }[];
  return rows.map((r) => ({ name: r.name, tier: r.tier, createdAt: r.created_at }));
}

/**
 * Delete a secret by name. Returns true if deleted.
 */
export function deleteSecret(db: DatabaseSync, name: string): boolean {
  const stmt = db.prepare('DELETE FROM secrets WHERE name = ?');
  const result = stmt.run(name);
  return result.changes > 0;
}

export const vault = {
  initVault,
  getConfig,
  setConfig,
  insertSecret,
  getSecret,
  getSecretById,
  listSecrets,
  deleteSecret,
};
