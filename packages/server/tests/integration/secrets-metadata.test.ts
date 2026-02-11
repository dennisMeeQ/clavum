import { ed25519, signatures, x25519 } from '@clavum/crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db.js';

let agentAId: string;
let agentAEdPriv: Uint8Array;
let agentBId: string;
let agentBEdPriv: Uint8Array;

function signedHeaders(
  agentId: string,
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

  const serverKeys = x25519.generateKeypair();
  const tenant = await prisma.tenant.create({
    data: {
      name: 'Secrets Test Tenant',
      x25519Private: Buffer.from(serverKeys.privateKey),
      x25519Public: Buffer.from(serverKeys.publicKey),
    },
  });

  // Agent A
  const aX = x25519.generateKeypair();
  const aEd = ed25519.generateKeypair();
  agentAEdPriv = aEd.privateKey;
  const agentA = await prisma.agent.create({
    data: {
      tenantId: tenant.id,
      name: 'agent-a',
      x25519Public: Buffer.from(aX.publicKey),
      ed25519Public: Buffer.from(aEd.publicKey),
    },
  });
  agentAId = agentA.id;

  // Agent B
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

describe('secrets metadata API', () => {
  it('should register a secret and list it', async () => {
    const body = JSON.stringify({
      secret_id: 'test-secret-001',
      name: 'db-password',
      tier: 'green',
    });
    const headers = signedHeaders(agentAId, agentAEdPriv, 'POST', '/api/secrets/register', body);

    const res = await app.request('/api/secrets/register', {
      method: 'POST',
      headers,
      body,
    });
    expect(res.status).toBe(201);
    const data = (await res.json()) as { id: string; name: string; tier: string };
    expect(data.name).toBe('db-password');
    expect(data.tier).toBe('green');

    // List
    const listBody = '';
    const listHeaders = signedHeaders(agentAId, agentAEdPriv, 'GET', '/api/secrets', listBody);
    const listRes = await app.request('/api/secrets', {
      method: 'GET',
      headers: listHeaders,
    });
    expect(listRes.status).toBe(200);
    const listData = (await listRes.json()) as { secrets: { name: string }[] };
    expect(listData.secrets).toHaveLength(1);
    expect(listData.secrets[0].name).toBe('db-password');
  });

  it('should not let agent A see agent B secrets', async () => {
    // Agent B registers a secret
    const body = JSON.stringify({
      secret_id: 'secret-b-001',
      name: 'b-secret',
      tier: 'green',
    });
    const headers = signedHeaders(agentBId, agentBEdPriv, 'POST', '/api/secrets/register', body);
    const res = await app.request('/api/secrets/register', {
      method: 'POST',
      headers,
      body,
    });
    expect(res.status).toBe(201);

    // Agent A lists — should not see B's secret
    const listHeaders = signedHeaders(agentAId, agentAEdPriv, 'GET', '/api/secrets', '');
    const listRes = await app.request('/api/secrets', {
      method: 'GET',
      headers: listHeaders,
    });
    const listData = (await listRes.json()) as { secrets: { name: string }[] };
    expect(listData.secrets).toHaveLength(0);
  });

  it('should not let agent A delete agent B secrets', async () => {
    // Agent B registers
    const body = JSON.stringify({
      secret_id: 'secret-b-002',
      name: 'b-secret-2',
      tier: 'green',
    });
    const regHeaders = signedHeaders(agentBId, agentBEdPriv, 'POST', '/api/secrets/register', body);
    await app.request('/api/secrets/register', {
      method: 'POST',
      headers: regHeaders,
      body,
    });

    // Agent A tries to delete
    const delHeaders = signedHeaders(
      agentAId,
      agentAEdPriv,
      'DELETE',
      '/api/secrets/secret-b-002',
      '',
    );
    const delRes = await app.request('/api/secrets/secret-b-002', {
      method: 'DELETE',
      headers: delHeaders,
    });
    expect(delRes.status).toBe(403);
  });

  it('should reject duplicate name for same agent', async () => {
    const body = JSON.stringify({
      secret_id: 'dup-001',
      name: 'same-name',
      tier: 'green',
    });
    const headers1 = signedHeaders(agentAId, agentAEdPriv, 'POST', '/api/secrets/register', body);
    const res1 = await app.request('/api/secrets/register', {
      method: 'POST',
      headers: headers1,
      body,
    });
    expect(res1.status).toBe(201);

    const body2 = JSON.stringify({
      secret_id: 'dup-002',
      name: 'same-name',
      tier: 'green',
    });
    const headers2 = signedHeaders(agentAId, agentAEdPriv, 'POST', '/api/secrets/register', body2);
    const res2 = await app.request('/api/secrets/register', {
      method: 'POST',
      headers: headers2,
      body: body2,
    });
    expect(res2.status).toBe(409);
  });
});
