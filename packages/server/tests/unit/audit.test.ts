import { ed25519, x25519 } from '@clavum/crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db.js';
import { createEntry, queryEntries } from '../../src/services/audit.js';

let agentId: string;
let secretId: string;

beforeAll(async () => {
  // Clean up
  await prisma.auditLog.deleteMany();
  await prisma.secretMetadata.deleteMany();
  await prisma.usedNonce.deleteMany();
  await prisma.pairingInvitation.deleteMany();
  await prisma.agent.deleteMany();
  await prisma.phone.deleteMany();
  await prisma.tenant.deleteMany();

  // Create tenant + agent + secret metadata
  const serverKeys = x25519.generateKeypair();
  const tenant = await prisma.tenant.create({
    data: {
      name: 'Audit Test Tenant',
      x25519Private: Buffer.from(serverKeys.privateKey),
      x25519Public: Buffer.from(serverKeys.publicKey),
    },
  });

  const agentKeys = x25519.generateKeypair();
  const edKeys = ed25519.generateKeypair();
  const agent = await prisma.agent.create({
    data: {
      tenantId: tenant.id,
      name: 'audit-test-agent',
      x25519Public: Buffer.from(agentKeys.publicKey),
      ed25519Public: Buffer.from(edKeys.publicKey),
    },
  });
  agentId = agent.id;

  const secret = await prisma.secretMetadata.create({
    data: {
      tenantId: tenant.id,
      agentId: agent.id,
      name: 'test-secret',
      tier: 'green',
    },
  });
  secretId = secret.id;
});

beforeEach(async () => {
  await prisma.auditLog.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('audit service', () => {
  it('should create an audit entry and store in DB', async () => {
    const id = await createEntry({
      agentId,
      secretId,
      reason: 'CI deployment needs DB password',
      tier: 'green',
      result: 'auto_granted',
      latencyMs: 42,
    });

    expect(id).toBeTruthy();

    const entry = await prisma.auditLog.findUnique({ where: { id } });
    expect(entry).not.toBeNull();
    expect(entry?.agentId).toBe(agentId);
    expect(entry?.secretId).toBe(secretId);
    expect(entry?.reason).toBe('CI deployment needs DB password');
    expect(entry?.tier).toBe('green');
    expect(entry?.result).toBe('auto_granted');
    expect(entry?.latencyMs).toBe(42);
  });

  it('should query entries by agent', async () => {
    await createEntry({
      agentId,
      secretId,
      reason: 'reason 1',
      tier: 'green',
      result: 'auto_granted',
    });

    const entries = await queryEntries({ agentId });
    expect(entries).toHaveLength(1);
    expect(entries[0].agentId).toBe(agentId);
  });

  it('should query entries by secret', async () => {
    await createEntry({
      agentId,
      secretId,
      reason: 'reason 2',
      tier: 'green',
      result: 'auto_granted',
    });

    const entries = await queryEntries({ secretId });
    expect(entries).toHaveLength(1);
    expect(entries[0].secretId).toBe(secretId);
  });

  it('should query entries by date range', async () => {
    await createEntry({
      agentId,
      secretId,
      reason: 'old reason',
      tier: 'green',
      result: 'auto_granted',
    });

    // Query for future range — should return nothing
    const futureEntries = await queryEntries({
      from: new Date(Date.now() + 60_000),
    });
    expect(futureEntries).toHaveLength(0);

    // Query including now
    const entries = await queryEntries({
      from: new Date(Date.now() - 60_000),
      to: new Date(Date.now() + 60_000),
    });
    expect(entries).toHaveLength(1);
  });

  it('should respect limit parameter', async () => {
    // Create 3 entries
    for (let i = 0; i < 3; i++) {
      await createEntry({
        agentId,
        secretId,
        reason: `reason ${i}`,
        tier: 'green',
        result: 'auto_granted',
      });
    }

    const entries = await queryEntries({ agentId, limit: 2 });
    expect(entries).toHaveLength(2);
  });
});
