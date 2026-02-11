import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db.js';

let tenantId: string;

beforeAll(async () => {
  // Clean test data (respect FK order)
  await prisma.auditLog.deleteMany();
  await prisma.approvalRequest.deleteMany();
  await prisma.secretMetadata.deleteMany();
  await prisma.usedNonce.deleteMany();
  await prisma.pairingInvitation.deleteMany();
  await prisma.agent.deleteMany();
  await prisma.phone.deleteMany();
  await prisma.tenant.deleteMany();

  // Create a tenant for testing
  const res = await app.request('/api/tenants', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Pairing Test Tenant' }),
  });
  const data = (await res.json()) as { id: string };
  tenantId = data.id;
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('POST /api/pair/invite', () => {
  beforeEach(async () => {
    await prisma.pairingInvitation.deleteMany();
  });

  it('creates invitation with 10-min expiry', async () => {
    const before = Date.now();
    const res = await app.request('/api/pair/invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId, type: 'agent' }),
    });

    expect(res.status).toBe(201);
    const data = (await res.json()) as {
      id: string;
      token: string;
      expiresAt: string;
      qr: { pub: string; token: string; url: string };
    };

    expect(data.id).toBeDefined();
    expect(data.token).toBeDefined();
    expect(data.token.length).toBeGreaterThan(0);

    // Expiry should be ~10 minutes from now
    const expiresAt = new Date(data.expiresAt).getTime();
    const expectedExpiry = before + 10 * 60 * 1000;
    expect(expiresAt).toBeGreaterThanOrEqual(expectedExpiry - 2000);
    expect(expiresAt).toBeLessThanOrEqual(expectedExpiry + 2000);
  });

  it('returns QR payload with valid pub + token + url', async () => {
    const res = await app.request('/api/pair/invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId, type: 'agent' }),
    });

    const data = (await res.json()) as {
      token: string;
      qr: { pub: string; token: string; url: string };
    };

    expect(data.qr).toBeDefined();
    expect(data.qr.pub).toBeDefined();
    expect(data.qr.token).toBe(data.token);
    expect(data.qr.url).toBeDefined();

    // pub should decode to 32 bytes (X25519 public key)
    const pubBytes = Buffer.from(data.qr.pub, 'base64url');
    expect(pubBytes.length).toBe(32);
  });

  it('generates unique tokens', async () => {
    const res1 = await app.request('/api/pair/invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId, type: 'agent' }),
    });
    const res2 = await app.request('/api/pair/invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId, type: 'agent' }),
    });

    const data1 = (await res1.json()) as { token: string };
    const data2 = (await res2.json()) as { token: string };

    expect(data1.token).not.toBe(data2.token);
  });

  it('rejects missing tenantId', async () => {
    const res = await app.request('/api/pair/invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'agent' }),
    });
    expect(res.status).toBe(400);
  });

  it('rejects invalid type', async () => {
    const res = await app.request('/api/pair/invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId, type: 'invalid' }),
    });
    expect(res.status).toBe(400);
  });

  it('rejects unknown tenant', async () => {
    const res = await app.request('/api/pair/invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenantId: '00000000-0000-0000-0000-000000000000',
        type: 'agent',
      }),
    });
    expect(res.status).toBe(404);
  });
});
