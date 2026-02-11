import { randomBytes, randomUUID } from 'node:crypto';
import {
  aes256gcm,
  ed25519,
  flows,
  fromBase64Url,
  signatures,
  toBase64Url,
  x25519,
} from '@clavum/crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db.js';

let tenantId: string;
let serverPriv: Uint8Array;
let serverPub: Uint8Array;
let agentId: string;
let agentEdPriv: Uint8Array;
let agentX25519Priv: Uint8Array;
let _agentX25519Pub: Uint8Array;
let agentBId: string;
let agentBEdPriv: Uint8Array;

function signedHeaders(
  aId: string,
  edPriv: Uint8Array,
  method: string,
  path: string,
  body: string,
) {
  const timestamp = Date.now().toString();
  const bodyBytes = new TextEncoder().encode(body);
  const sig = signatures.signRequest(edPriv, timestamp, method, path, bodyBytes);
  return {
    'Content-Type': 'application/json',
    'X-Agent-Id': aId,
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

  const sKeys = x25519.generateKeypair();
  serverPriv = sKeys.privateKey;
  serverPub = sKeys.publicKey;

  const tenant = await prisma.tenant.create({
    data: {
      name: 'Retrieve Test Tenant',
      x25519Private: Buffer.from(serverPriv),
      x25519Public: Buffer.from(serverPub),
    },
  });
  tenantId = tenant.id;

  // Agent A (main test agent)
  const aX = x25519.generateKeypair();
  agentX25519Priv = aX.privateKey;
  _agentX25519Pub = aX.publicKey;
  const aEd = ed25519.generateKeypair();
  agentEdPriv = aEd.privateKey;
  const agentA = await prisma.agent.create({
    data: {
      tenantId: tenant.id,
      name: 'retrieve-agent',
      x25519Public: Buffer.from(aX.publicKey),
      ed25519Public: Buffer.from(aEd.publicKey),
    },
  });
  agentId = agentA.id;

  // Agent B (for isolation tests)
  const bX = x25519.generateKeypair();
  const bEd = ed25519.generateKeypair();
  agentBEdPriv = bEd.privateKey;
  const agentB = await prisma.agent.create({
    data: {
      tenantId: tenant.id,
      name: 'agent-b',
      x25519Public: Buffer.from(bX.publicKey),
      ed25519Public: Buffer.from(bEd.publicKey),
    },
  });
  agentBId = agentB.id;
});

beforeEach(async () => {
  await prisma.auditLog.deleteMany();
  await prisma.secretMetadata.deleteMany();
  await prisma.usedNonce.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('green retrieval API', () => {
  it('should return enc_kek for a full green retrieval flow', async () => {
    const secretId = randomUUID();

    // Register secret metadata
    await prisma.secretMetadata.create({
      data: {
        id: secretId,
        tenantId,
        agentId,
        name: 'green-secret',
        tier: 'green',
      },
    });

    // Agent side: generate ephemeral keypair and kek_salt
    const eph = x25519.generateKeypair();
    const kekSalt = new Uint8Array(randomBytes(32));

    const body = JSON.stringify({
      eph_x25519_pub: toBase64Url(eph.publicKey),
      kek_salt: toBase64Url(kekSalt),
      reason: 'CI deployment',
    });

    const path = `/api/secrets/${secretId}/retrieve`;
    const headers = signedHeaders(agentId, agentEdPriv, 'POST', path, body);

    const res = await app.request(path, { method: 'POST', headers, body });
    expect(res.status).toBe(200);

    const data = (await res.json()) as {
      enc_kek: string;
      enc_kek_iv: string;
      enc_kek_tag: string;
    };
    expect(data.enc_kek).toBeTruthy();
    expect(data.enc_kek_iv).toBeTruthy();
    expect(data.enc_kek_tag).toBeTruthy();
  });

  it('should allow agent to decrypt enc_kek and recover the correct KEK', async () => {
    const secretId = randomUUID();

    await prisma.secretMetadata.create({
      data: { id: secretId, tenantId, agentId, name: 'decrypt-test', tier: 'green' },
    });

    const eph = x25519.generateKeypair();
    const kekSalt = new Uint8Array(randomBytes(32));

    const body = JSON.stringify({
      eph_x25519_pub: toBase64Url(eph.publicKey),
      kek_salt: toBase64Url(kekSalt),
      reason: 'decrypt test',
    });

    const path = `/api/secrets/${secretId}/retrieve`;
    const headers = signedHeaders(agentId, agentEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });
    const data = (await res.json()) as {
      enc_kek: string;
      enc_kek_iv: string;
      enc_kek_tag: string;
    };

    // Agent derives K_session the same way server does
    const kSession = x25519.sharedSecret(agentX25519Priv, serverPub);

    // Decrypt enc_kek
    const decryptedKek = aes256gcm.decrypt(
      kSession,
      fromBase64Url(data.enc_kek),
      fromBase64Url(data.enc_kek_iv),
      new Uint8Array(0),
      fromBase64Url(data.enc_kek_tag),
    );

    // Agent also derives KEK locally (using ephemeral priv + server pub)
    const expectedKek = flows.deriveGreenKek(eph.privateKey, serverPub, kekSalt, secretId);

    expect(Buffer.from(decryptedKek).toString('hex')).toBe(
      Buffer.from(expectedKek).toString('hex'),
    );
  });

  it('should allow full end-to-end: encrypt → store → retrieve → decrypt', async () => {
    const secretId = randomUUID();
    const plaintext = new TextEncoder().encode('super-secret-password-123');

    // Agent side: generate DEK, encrypt secret
    const dek = new Uint8Array(randomBytes(32));
    const aad = new Uint8Array(0);
    const { encryptedBlob, blobIv, blobTag } = flows.encryptSecret(dek, plaintext, aad);

    // Agent: generate ephemeral keys, kek_salt, wrap DEK
    const eph = x25519.generateKeypair();
    const kekSalt = new Uint8Array(randomBytes(32));
    const kek = flows.deriveGreenKek(eph.privateKey, serverPub, kekSalt, secretId);
    const { encryptedDek, dekIv, dekTag } = flows.wrapDek(kek, dek, aad);

    // Register on server
    await prisma.secretMetadata.create({
      data: { id: secretId, tenantId, agentId, name: 'e2e-secret', tier: 'green' },
    });

    // Retrieve KEK from server
    const body = JSON.stringify({
      eph_x25519_pub: toBase64Url(eph.publicKey),
      kek_salt: toBase64Url(kekSalt),
      reason: 'e2e test',
    });
    const path = `/api/secrets/${secretId}/retrieve`;
    const headers = signedHeaders(agentId, agentEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });
    expect(res.status).toBe(200);

    const data = (await res.json()) as {
      enc_kek: string;
      enc_kek_iv: string;
      enc_kek_tag: string;
    };

    // Decrypt KEK from transport
    const kSession = x25519.sharedSecret(agentX25519Priv, serverPub);
    const recoveredKek = aes256gcm.decrypt(
      kSession,
      fromBase64Url(data.enc_kek),
      fromBase64Url(data.enc_kek_iv),
      new Uint8Array(0),
      fromBase64Url(data.enc_kek_tag),
    );

    // Unwrap DEK with recovered KEK
    const recoveredDek = flows.unwrapDek(recoveredKek, encryptedDek, dekIv, aad, dekTag);

    // Decrypt secret with recovered DEK
    const recoveredPlaintext = flows.decryptSecret(
      recoveredDek,
      encryptedBlob,
      blobIv,
      aad,
      blobTag,
    );

    expect(new TextDecoder().decode(recoveredPlaintext)).toBe('super-secret-password-123');
  });

  it('should return 403 for wrong agent', async () => {
    const secretId = randomUUID();
    await prisma.secretMetadata.create({
      data: { id: secretId, tenantId, agentId, name: 'agent-a-only', tier: 'green' },
    });

    const eph = x25519.generateKeypair();
    const body = JSON.stringify({
      eph_x25519_pub: toBase64Url(eph.publicKey),
      kek_salt: toBase64Url(new Uint8Array(randomBytes(32))),
      reason: 'unauthorized',
    });

    const path = `/api/secrets/${secretId}/retrieve`;
    const headers = signedHeaders(agentBId, agentBEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });
    expect(res.status).toBe(403);
  });

  it('should return 404 for non-existent secret', async () => {
    const body = JSON.stringify({
      eph_x25519_pub: toBase64Url(x25519.generateKeypair().publicKey),
      kek_salt: toBase64Url(new Uint8Array(randomBytes(32))),
      reason: 'nonexistent',
    });

    const path = '/api/secrets/00000000-0000-0000-0000-000000000000/retrieve';
    const headers = signedHeaders(agentId, agentEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });
    expect(res.status).toBe(404);
  });

  it('should return 400 for missing reason', async () => {
    const secretId = randomUUID();
    await prisma.secretMetadata.create({
      data: { id: secretId, tenantId, agentId, name: 'no-reason', tier: 'green' },
    });

    const body = JSON.stringify({
      eph_x25519_pub: toBase64Url(x25519.generateKeypair().publicKey),
      kek_salt: toBase64Url(new Uint8Array(randomBytes(32))),
    });

    const path = `/api/secrets/${secretId}/retrieve`;
    const headers = signedHeaders(agentId, agentEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });
    expect(res.status).toBe(400);
  });

  it('should write audit log on retrieval', async () => {
    const secretId = randomUUID();
    await prisma.secretMetadata.create({
      data: { id: secretId, tenantId, agentId, name: 'audit-check', tier: 'green' },
    });

    const eph = x25519.generateKeypair();
    const body = JSON.stringify({
      eph_x25519_pub: toBase64Url(eph.publicKey),
      kek_salt: toBase64Url(new Uint8Array(randomBytes(32))),
      reason: 'audit test reason',
    });

    const path = `/api/secrets/${secretId}/retrieve`;
    const headers = signedHeaders(agentId, agentEdPriv, 'POST', path, body);
    await app.request(path, { method: 'POST', headers, body });

    const logs = await prisma.auditLog.findMany({
      where: { secretId, agentId },
    });

    expect(logs).toHaveLength(1);
    expect(logs[0].reason).toBe('audit test reason');
    expect(logs[0].result).toBe('auto_granted');
    expect(logs[0].tier).toBe('green');
  });
});
