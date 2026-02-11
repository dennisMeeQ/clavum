/**
 * Full end-to-end integration test.
 *
 * Golden path: create tenant → pair agent → store secret → retrieve → verify plaintext.
 */

import { randomBytes, randomUUID } from 'node:crypto';
import {
  aes256gcm,
  ed25519,
  flows,
  fromBase64Url,
  kdf,
  signatures,
  toBase64Url,
  x25519,
} from '@clavum/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db.js';

// Server-side state
let tenantId: string;
let serverPub: Uint8Array;

// Agent-side keys
let agentId: string;
let agentX25519Priv: Uint8Array;
let agentX25519Pub: Uint8Array;
let agentEdPriv: Uint8Array;

function signedHeaders(method: string, path: string, body: string) {
  const timestamp = Date.now().toString();
  const bodyBytes = new TextEncoder().encode(body);
  const sig = signatures.signRequest(agentEdPriv, timestamp, method, path, bodyBytes);
  return {
    'Content-Type': 'application/json',
    'X-Agent-Id': agentId,
    'X-Timestamp': timestamp,
    'X-Signature': Buffer.from(sig).toString('base64url'),
  };
}

beforeAll(async () => {
  await prisma.auditLog.deleteMany();
  await prisma.approvalRequest.deleteMany();
  await prisma.secretMetadata.deleteMany();
  await prisma.usedNonce.deleteMany();
  await prisma.pairingInvitation.deleteMany();
  await prisma.agent.deleteMany();
  await prisma.phone.deleteMany();
  await prisma.tenant.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('full green-tier flow', () => {
  it('should complete: tenant → pair → store → retrieve → decrypt', async () => {
    // Step 1: Create tenant
    const tenantRes = await app.request('/api/tenants', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Full Flow Tenant' }),
    });
    expect(tenantRes.status).toBe(201);
    const tenantData = (await tenantRes.json()) as {
      id: string;
      x25519Public: string;
    };
    tenantId = tenantData.id;
    serverPub = fromBase64Url(tenantData.x25519Public);

    // Step 2: Create pairing invitation
    const inviteRes = await app.request('/api/pair/invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId, type: 'agent' }),
    });
    expect(inviteRes.status).toBe(201);
    const inviteData = (await inviteRes.json()) as { token: string };

    // Step 3: Pair agent
    const aX = x25519.generateKeypair();
    agentX25519Priv = aX.privateKey;
    agentX25519Pub = aX.publicKey;
    const aEd = ed25519.generateKeypair();
    agentEdPriv = aEd.privateKey;

    const pairRes = await app.request('/api/pair/agent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: inviteData.token,
        x25519_pub: toBase64Url(aX.publicKey),
        ed25519_pub: toBase64Url(aEd.publicKey),
        name: 'full-flow-agent',
      }),
    });
    expect(pairRes.status).toBe(200);
    const pairData = (await pairRes.json()) as { agentId: string; fingerprint: string };
    agentId = pairData.agentId;

    // Step 4: Store a secret (agent-side crypto)
    const secretId = randomUUID();
    const plaintext = new TextEncoder().encode('my-database-password-42!');
    const dek = new Uint8Array(randomBytes(32));
    const aad = new Uint8Array(0);

    // Encrypt plaintext with DEK
    const { encryptedBlob, blobIv, blobTag } = flows.encryptSecret(dek, plaintext, aad);

    // Generate ephemeral keys, derive KEK, wrap DEK
    const eph = x25519.generateKeypair();
    const kekSalt = new Uint8Array(randomBytes(32));
    const kek = flows.deriveGreenKek(eph.privateKey, serverPub, kekSalt, secretId);
    const { encryptedDek, dekIv, dekTag } = flows.wrapDek(kek, dek, aad);

    // Register metadata on server
    const regBody = JSON.stringify({ secret_id: secretId, name: 'db-password', tier: 'green' });
    const regHeaders = signedHeaders('POST', '/api/secrets/register', regBody);
    const regRes = await app.request('/api/secrets/register', {
      method: 'POST',
      headers: regHeaders,
      body: regBody,
    });
    expect(regRes.status).toBe(201);

    // Step 5: Retrieve KEK from server
    const retrieveBody = JSON.stringify({
      eph_x25519_pub: toBase64Url(eph.publicKey),
      kek_salt: toBase64Url(kekSalt),
      reason: 'full flow integration test',
    });
    const retrievePath = `/api/secrets/${secretId}/retrieve`;
    const retrieveHeaders = signedHeaders('POST', retrievePath, retrieveBody);
    const retrieveRes = await app.request(retrievePath, {
      method: 'POST',
      headers: retrieveHeaders,
      body: retrieveBody,
    });
    expect(retrieveRes.status).toBe(200);

    const retrieveData = (await retrieveRes.json()) as {
      enc_kek: string;
      enc_kek_iv: string;
      enc_kek_tag: string;
    };

    // Step 6: Decrypt KEK from transport
    const kSession = x25519.sharedSecret(agentX25519Priv, serverPub);
    const recoveredKek = aes256gcm.decrypt(
      kSession,
      fromBase64Url(retrieveData.enc_kek),
      fromBase64Url(retrieveData.enc_kek_iv),
      new Uint8Array(0),
      fromBase64Url(retrieveData.enc_kek_tag),
    );

    // Step 7: Unwrap DEK
    const recoveredDek = flows.unwrapDek(recoveredKek, encryptedDek, dekIv, aad, dekTag);

    // Step 8: Decrypt plaintext
    const recoveredPlaintext = flows.decryptSecret(
      recoveredDek,
      encryptedBlob,
      blobIv,
      aad,
      blobTag,
    );

    expect(new TextDecoder().decode(recoveredPlaintext)).toBe('my-database-password-42!');

    // Step 9: Verify audit log
    const auditHeaders = signedHeaders('GET', '/api/audit', '');
    const auditRes = await app.request(`/api/audit?secret_id=${secretId}`, {
      method: 'GET',
      headers: auditHeaders,
    });
    expect(auditRes.status).toBe(200);

    const auditData = (await auditRes.json()) as {
      entries: { reason: string; result: string }[];
    };
    expect(auditData.entries).toHaveLength(1);
    expect(auditData.entries[0].reason).toBe('full flow integration test');
    expect(auditData.entries[0].result).toBe('auto_granted');
  });
});
