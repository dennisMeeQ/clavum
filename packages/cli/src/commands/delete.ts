/**
 * clavum delete <name> [--force] — Delete a secret from vault and server.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import type { SignedFetchConfig } from '../http.js';
import { signedFetch } from '../http.js';
import { keystore } from '../keystore.js';
import { deleteSecret, getConfig, getSecret, initVault } from '../vault.js';

export interface DeleteOptions {
  name: string;
  force?: boolean;
}

export async function del(options: DeleteOptions): Promise<void> {
  const { name, force } = options;

  const dbPath = join(homedir(), '.clavum', 'vault.db');
  const db = initVault(dbPath);

  const record = getSecret(db, name);
  if (!record) {
    console.error(`Error: Secret "${name}" not found.`);
    db.close();
    process.exit(1);
  }

  // Confirm unless --force
  if (!force) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise<string>((resolve) => {
      rl.question(`Delete secret "${name}" (${record.tier})? [y/N] `, resolve);
    });
    rl.close();

    if (answer.toLowerCase() !== 'y') {
      console.log('Cancelled.');
      db.close();
      return;
    }
  }

  // Delete from local vault
  deleteSecret(db, name);

  // Delete from server
  const ed25519Priv = keystore.load('agent_ed25519_priv');
  const serverUrl = getConfig(db, 'server_url');
  const agentId = getConfig(db, 'agent_id');

  if (ed25519Priv && serverUrl && agentId) {
    const fetchConfig: SignedFetchConfig = { agentId, ed25519Priv, serverUrl };
    try {
      await signedFetch('DELETE', `/api/secrets/${record.id}`, null, fetchConfig);
    } catch {
      console.error('Warning: Failed to delete from server. Local vault entry removed.');
    }
  }

  console.log(`🗑️ Secret "${name}" deleted.`);
  db.close();
}
