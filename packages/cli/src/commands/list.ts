/**
 * clavum list — List all secrets in the local vault.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { initVault, listSecrets } from '../vault.js';

export interface ListOptions {
  json?: boolean;
}

export function list(options: ListOptions): void {
  const dbPath = join(homedir(), '.clavum', 'vault.db');
  const db = initVault(dbPath);
  const secrets = listSecrets(db);

  if (options.json) {
    console.log(JSON.stringify(secrets));
  } else if (secrets.length === 0) {
    console.log('No secrets stored.');
  } else {
    console.log('Name                Tier     Created');
    console.log('─'.repeat(50));
    for (const s of secrets) {
      const name = s.name.padEnd(20);
      const tier = s.tier.padEnd(9);
      console.log(`${name}${tier}${s.createdAt}`);
    }
  }

  db.close();
}
