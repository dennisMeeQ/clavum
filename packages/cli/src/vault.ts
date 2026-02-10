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

export const vault = { initVault, getConfig, setConfig };
