#!/usr/bin/env node

/**
 * Clavum CLI — Secret management for AI agents
 *
 * Usage:
 *   clavum get <name> --reason "..."    Retrieve a secret
 *   clavum store <name> --tier green    Store a secret
 *   clavum list                         List secrets
 *   clavum audit [name]                 View audit log
 *   clavum pair <server-url>            Pair with a server
 */

import { pair } from './commands/pair.js';

const args = process.argv.slice(2);
const command = args[0];

function getFlag(name: string): string | undefined {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

async function main() {
  switch (command) {
    case 'pair': {
      const serverUrl = args[1];
      const token = getFlag('token');

      if (!serverUrl || !token) {
        console.error('Usage: clavum pair <server-url> --token <token>');
        process.exit(1);
      }

      await pair({ serverUrl, token, name: getFlag('name') });
      break;
    }
    case 'get':
    case 'store':
    case 'list':
    case 'audit':
      console.error(`TODO: ${command} not yet implemented`);
      process.exit(1);
      break;
    default:
      console.log(`🔑 Clavum CLI v0.0.1

Usage:
  clavum get <name> --reason "..."    Retrieve a secret
  clavum store <name> --tier green    Store a secret
  clavum list                         List secrets
  clavum audit [name]                 View audit log
  clavum pair <server-url>            Pair with a server

Options:
  --json        Output as JSON
  --timeout     Approval timeout in seconds (default: 300)`);
  }
}

main().catch((err: Error) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
