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

const command = process.argv[2];

switch (command) {
  case 'get':
  case 'store':
  case 'list':
  case 'audit':
  case 'pair':
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
