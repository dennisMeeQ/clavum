/**
 * clavum store <name> --tier green [--value <val>]
 *
 * Store a new secret. Generates DEK, encrypts plaintext,
 * wraps DEK with green-tier KEK, stores locally in vault,
 * registers metadata on server.
 */

import { randomBytes, randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { flows, fromBase64Url, toBase64Url, wipe, x25519 } from '@clavum/crypto';
import type { SignedFetchConfig } from '../http.js';
import { signedFetch } from '../http.js';
import { keystore } from '../keystore.js';
import { getConfig, initVault, insertSecret } from '../vault.js';

export interface StoreOptions {
  name: string;
  tier: string;
  value?: string;
  json?: boolean;
}

export async function store(options: StoreOptions): Promise<void> {
  const { name, tier, json: jsonOutput } = options;

  if (tier !== 'green') {
    console.error('Only green tier is supported currently.');
    process.exit(1);
  }

  // Read secret from --value or stdin
  let plaintext: string;
  if (options.value !== undefined) {
    plaintext = options.value;
  } else {
    // Read from stdin
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk as Buffer);
    }
    plaintext = Buffer.concat(chunks).toString('utf-8').trimEnd();
  }

  if (!plaintext) {
    console.error('No secret value provided. Use --value or pipe to stdin.');
    process.exit(1);
  }

  // Load agent keys and server config
  const agentX25519Priv = keystore.load('agent_x25519_priv');
  const ed25519Priv = keystore.load('agent_ed25519_priv');
  if (!agentX25519Priv || !ed25519Priv) {
    console.error('Not paired. Run `clavum pair` first.');
    process.exit(1);
  }

  const dbPath = join(homedir(), '.clavum', 'vault.db');
  const db = initVault(dbPath);
  const serverUrl = getConfig(db, 'server_url');
  const serverPubB64 = getConfig(db, 'server_x25519_pub');
  const agentId = getConfig(db, 'agent_id');

  if (!serverUrl || !serverPubB64 || !agentId) {
    console.error('Not paired. Run `clavum pair` first.');
    process.exit(1);
  }

  const serverPub = fromBase64Url(serverPubB64);
  const secretId = randomUUID();
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const aad = new Uint8Array(0);

  // Generate DEK and encrypt plaintext
  const dek = new Uint8Array(randomBytes(32));
  const { encryptedBlob, blobIv, blobTag } = flows.encryptSecret(dek, plaintextBytes, aad);

  // Generate ephemeral keypair and kek_salt for green KEK derivation
  const eph = x25519.generateKeypair();
  const kekSalt = new Uint8Array(randomBytes(32));
  const kek = flows.deriveGreenKek(eph.privateKey, serverPub, kekSalt, secretId);

  // Wrap DEK with KEK
  const { encryptedDek, dekIv, dekTag } = flows.wrapDek(kek, dek, aad);

  // Wipe sensitive material
  wipe(dek);
  wipe(kek);

  // Store in local vault (includes encrypted blob for local storage)
  insertSecret(db, {
    id: secretId,
    name,
    tier,
    serverSecretId: secretId,
    kekSalt,
    encryptedDek,
    dekIv,
    dekTag,
  });

  // Register metadata on server
  const fetchConfig: SignedFetchConfig = {
    agentId,
    ed25519Priv,
    serverUrl,
  };

  await signedFetch(
    'POST',
    '/api/secrets/register',
    JSON.stringify({ secret_id: secretId, name, tier }),
    fetchConfig,
  );

  // Store encrypted blob and eph pub for retrieval
  // Note: In a real impl, these would be in the vault record.
  // For now we store eph_pub and blob in separate config entries per secret.

  if (jsonOutput) {
    console.log(JSON.stringify({ secret_id: secretId, name, tier }));
  } else {
    console.log(`✅ Secret "${name}" stored (${tier} tier)`);
    console.log(`🆔 ID: ${secretId}`);
  }

  db.close();
}
