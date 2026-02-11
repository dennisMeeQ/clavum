import { randomBytes, randomUUID } from 'node:crypto';
import { ed25519, signatures, toBase64Url, x25519 } from '@clavum/crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db.js';

let tenantId: string;
let agentAId: string;
let agentAEdPriv: Uint8Array;
let agentBId: string;
let agentBEdPriv: Uint8Array;
let secretAId: string;
let secretBId: string;

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
  const tenant = await prisma.tenant.create({
    data: {
      name: 'Audit API Tenant',
      x25519Private: Buffer.from(sKeys.privateKey),
      x25519Public: Buffer.from(sKeys.publicKey),
    },
  });
  tenantId = tenant.id;

  // Agent A
  const aX = x25519.generateKeypair();
  const aEd = ed25519.generateKeypair();
  agentAEdPriv = aEd.privateKey;
  const agentA = await prisma.agent.create({
    data: {
      tenantId: tenant.id,
      name: 'audit-agent-a',
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
      name: 'audit-agent-b',
      x25519Public: Buffer.from(bX.publicKey),
      ed25519Public: Buffer.from(bEd.publicKey),
    },
  });
  agentBId = agentB.id;

  // Secrets
  secretAId = randomUUID();
  await prisma.secretMetadata.create({
    data: {
      id: secretAId,
      tenantId: tenant.id,
      agentId: agentAId,
      name: 'secret-a',
      tier: 'green',
    },
  });
  secretBId = randomUUID();
  await prisma.secretMetadata.create({
    data: {
      id: secretBId,
      tenantId: tenant.id,
      agentId: agentBId,
      name: 'secret-b',
      tier: 'green',
    },
  });
});

beforeEach(async () => {
  await prisma.auditLog.deleteMany();
  await prisma.usedNonce.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

async function createAuditEntry(agentId: string, secretId: string, reason: string) {
  await prisma.auditLog.create({
    data: { agentId, secretId, reason, tier: 'green', result: 'auto_granted' },
  });
}

describe('audit query API', () => {
  it('should return entries after retrieval', async () => {
    await createAuditEntry(agentAId, secretAId, 'deploy reason');

    const headers = signedHeaders(agentAId, agentAEdPriv, 'GET', '/api/audit', '');
    const res = await app.request('/api/audit', { method: 'GET', headers });

    expect(res.status).toBe(200);
    const data = (await res.json()) as { entries: { reason: string }[] };
    expect(data.entries).toHaveLength(1);
    expect(data.entries[0].reason).toBe('deploy reason');
  });

  it('should filter by secret_id', async () => {
    await createAuditEntry(agentAId, secretAId, 'first');

    const headers = signedHeaders(agentAId, agentAEdPriv, 'GET', '/api/audit', '');
    const res = await app.request(`/api/audit?secret_id=${secretAId}`, {
      method: 'GET',
      headers,
    });

    const data = (await res.json()) as { entries: { reason: string }[] };
    expect(data.entries).toHaveLength(1);
  });

  it('should filter by date range', async () => {
    await createAuditEntry(agentAId, secretAId, 'recent');

    // Future range
    const future = new Date(Date.now() + 60_000).toISOString();
    const headers = signedHeaders(agentAId, agentAEdPriv, 'GET', '/api/audit', '');
    const res = await app.request(`/api/audit?from=${future}`, { method: 'GET', headers });

    const data = (await res.json()) as { entries: unknown[] };
    expect(data.entries).toHaveLength(0);
  });

  it('should not let agent A see agent B audit entries', async () => {
    // Create entry for agent B's secret
    await createAuditEntry(agentBId, secretBId, 'b-reason');

    // Agent A queries
    const headers = signedHeaders(agentAId, agentAEdPriv, 'GET', '/api/audit', '');
    const res = await app.request('/api/audit', { method: 'GET', headers });

    const data = (await res.json()) as { entries: unknown[] };
    expect(data.entries).toHaveLength(0);
  });
});
