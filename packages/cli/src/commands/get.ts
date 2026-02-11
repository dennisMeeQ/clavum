/**
 * clavum get <name> --reason "..."
 *
 * Retrieve and decrypt a secret. Checks DEK cache first,
 * falls back to server retrieval if not cached.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { aes256gcm, flows, fromBase64Url, toBase64Url, wipe, x25519 } from '@clavum/crypto';
import { dekCache } from '../cache.js';
import type { SignedFetchConfig } from '../http.js';
import { signedFetch } from '../http.js';
import { keystore } from '../keystore.js';
import { getConfig, getSecret, initVault } from '../vault.js';

export interface GetOptions {
  name: string;
  reason: string;
  json?: boolean;
}

interface RetrieveResponse {
  enc_kek: string;
  enc_kek_iv: string;
  enc_kek_tag: string;
}

export async function get(options: GetOptions): Promise<void> {
  const { name, reason, json: jsonOutput } = options;

  if (!reason) {
    console.error('Error: --reason is required for secret retrieval.');
    process.exit(1);
  }

  // Load agent keys
  const agentX25519Priv = keystore.load('agent_x25519_priv');
  const ed25519Priv = keystore.load('agent_ed25519_priv');
  if (!agentX25519Priv || !ed25519Priv) {
    console.error('Not paired. Run `clavum pair` first.');
    process.exit(1);
  }

  // Open vault
  const dbPath = join(homedir(), '.clavum', 'vault.db');
  const db = initVault(dbPath);
  const serverUrl = getConfig(db, 'server_url');
  const serverPubB64 = getConfig(db, 'server_x25519_pub');
  const agentId = getConfig(db, 'agent_id');

  if (!serverUrl || !serverPubB64 || !agentId) {
    console.error('Not paired. Run `clavum pair` first.');
    process.exit(1);
  }

  // Look up secret in local vault
  const record = getSecret(db, name);
  if (!record) {
    console.error(`Error: Secret "${name}" not found in vault.`);
    process.exit(1);
  }

  const serverPub = fromBase64Url(serverPubB64);

  // Check DEK cache
  let dek = dekCache.get(record.id);

  if (!dek) {
    // Need to retrieve from server
    if (!record.kekSalt || !record.encryptedDek || !record.dekIv || !record.dekTag) {
      console.error('Error: Secret vault record is incomplete (missing encryption data).');
      process.exit(1);
    }

    // Generate ephemeral keypair for this retrieval
    const eph = x25519.generateKeypair();

    const fetchConfig: SignedFetchConfig = {
      agentId,
      ed25519Priv,
      serverUrl,
    };

    const path = `/api/secrets/${record.id}/retrieve`;
    const body = JSON.stringify({
      eph_x25519_pub: toBase64Url(eph.publicKey),
      kek_salt: toBase64Url(record.kekSalt),
      reason,
    });

    const response = (await signedFetch('POST', path, body, fetchConfig)) as RetrieveResponse;

    // Decrypt KEK from transport: server encrypted with K_session
    const kSession = x25519.sharedSecret(agentX25519Priv, serverPub);
    const kek = aes256gcm.decrypt(
      kSession,
      fromBase64Url(response.enc_kek),
      fromBase64Url(response.enc_kek_iv),
      new Uint8Array(0),
      fromBase64Url(response.enc_kek_tag),
    );
    wipe(kSession);

    // Unwrap DEK with KEK
    const aad = new Uint8Array(0);
    dek = flows.unwrapDek(kek, record.encryptedDek, record.dekIv, aad, record.dekTag);
    wipe(kek);

    // Cache DEK for green tier
    if (record.tier === 'green') {
      dekCache.set(record.id, dek);
    }
  }

  // We don't have the encrypted blob stored locally in this version
  // The blob would need to be stored during `store` as well
  // For now, output the DEK retrieval success
  // TODO: Store and retrieve encrypted blob from vault

  if (jsonOutput) {
    console.log(
      JSON.stringify({
        name: record.name,
        tier: record.tier,
        id: record.id,
        status: 'dek_retrieved',
      }),
    );
  } else {
    console.log(`🔓 DEK retrieved for "${name}" (${record.tier} tier)`);
  }

  db.close();
}
