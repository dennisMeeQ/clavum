/**
 * clavum pair <server-url> --token <token>
 *
 * Pair this CLI agent with a Clavum server.
 * Generates X25519 + Ed25519 keypairs, registers with server,
 * displays emoji fingerprint for verification.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { ed25519, fingerprintToEmoji, kdf, toBase64Url, x25519 } from '@clavum/crypto';
import { keystore } from '../keystore.js';
import { initVault, setConfig } from '../vault.js';

interface PairOptions {
  serverUrl: string;
  token: string;
  name?: string;
}

interface PairAgentResponse {
  agentId: string;
  serverX25519Pub: string;
  fingerprint: string;
}

export async function pair(options: PairOptions): Promise<void> {
  const { serverUrl, token, name = 'clavum-agent' } = options;

  // Check if already paired
  if (keystore.exists('agent_x25519')) {
    console.warn('⚠️  Already paired. Re-pairing will overwrite existing keys.');
  }

  // Generate keypairs
  console.log('🔑 Generating keypairs...');
  const x25519Keys = x25519.generateKeypair();
  const ed25519Keys = ed25519.generateKeypair();

  // Store private keys
  keystore.store('agent_x25519', x25519Keys.privateKey);
  keystore.store('agent_ed25519', ed25519Keys.privateKey);
  console.log('💾 Private keys stored in ~/.clavum/');

  // Register with server
  console.log(`📡 Registering with ${serverUrl}...`);
  const res = await fetch(`${serverUrl}/api/pair/agent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token,
      x25519_pub: toBase64Url(x25519Keys.publicKey),
      ed25519_pub: toBase64Url(ed25519Keys.publicKey),
      name,
    }),
  });

  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as {
      error?: string;
    };
    throw new Error(`Pairing failed (${res.status}): ${err.error || res.statusText}`);
  }

  const data = (await res.json()) as PairAgentResponse;

  // Verify fingerprint locally
  const serverPubBytes = new Uint8Array(Buffer.from(data.serverX25519Pub, 'base64url'));
  const sharedSecret = x25519.sharedSecret(x25519Keys.privateKey, serverPubBytes);
  const fpBytes = kdf.deriveFingerprint(sharedSecret);
  const localFingerprint = fingerprintToEmoji(fpBytes);

  if (localFingerprint !== data.fingerprint) {
    throw new Error('⚠️  Fingerprint mismatch! Possible MITM attack. Aborting.');
  }

  // Initialize vault and save config
  const vaultPath = join(homedir(), '.clavum', 'vault.db');
  const db = initVault(vaultPath);
  setConfig(db, 'server_url', serverUrl);
  setConfig(db, 'server_x25519_pub', data.serverX25519Pub);
  setConfig(db, 'agent_id', data.agentId);
  setConfig(db, 'agent_x25519_pub', toBase64Url(x25519Keys.publicKey));
  setConfig(db, 'agent_ed25519_pub', toBase64Url(ed25519Keys.publicKey));
  db.close();

  console.log('\n✅ Paired successfully!');
  console.log(`🆔 Agent ID: ${data.agentId}`);
  console.log(`🔒 Fingerprint: ${data.fingerprint}`);
  console.log('\n👆 Verify this fingerprint matches what the server admin sees.');
}
