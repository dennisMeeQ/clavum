/**
 * Key storage for Clavum CLI.
 *
 * Tries OS Keychain first, falls back to file storage.
 * File fallback: ~/.clavum/<name>.key with chmod 600.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const CLAVUM_DIR = join(homedir(), '.clavum');
const FILE_MODE = 0o600;

function ensureDir(): void {
  if (!existsSync(CLAVUM_DIR)) {
    mkdirSync(CLAVUM_DIR, { recursive: true, mode: 0o700 });
  }
}

function keyPath(name: string): string {
  // Sanitize name to prevent path traversal
  const safe = name.replace(/[^a-zA-Z0-9_-]/g, '_');
  return join(CLAVUM_DIR, `${safe}.key`);
}

/**
 * Store a key. Uses file-based storage (~/.clavum/<name>.key).
 */
export function store(name: string, key: Uint8Array): void {
  ensureDir();
  const path = keyPath(name);
  writeFileSync(path, Buffer.from(key), { mode: FILE_MODE });
}

/**
 * Load a key by name. Returns null if not found.
 */
export function load(name: string): Uint8Array | null {
  const path = keyPath(name);
  if (!existsSync(path)) {
    return null;
  }
  const data = readFileSync(path);
  return new Uint8Array(data);
}

/**
 * Check if a key exists.
 */
export function exists(name: string): boolean {
  return existsSync(keyPath(name));
}

export const keystore = { store, load, exists };
