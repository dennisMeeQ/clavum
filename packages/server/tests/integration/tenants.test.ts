import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db.js';

beforeAll(async () => {
  // Clean test data
  await prisma.pairingInvitation.deleteMany();
  await prisma.agent.deleteMany();
  await prisma.phone.deleteMany();
  await prisma.secret.deleteMany();
  await prisma.tenant.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('POST /api/tenants', () => {
  it('creates tenant with keypair', async () => {
    const res = await app.request('/api/tenants', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Test Tenant' }),
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.name).toBe('Test Tenant');
    expect(data.id).toBeDefined();
    expect(data.x25519Public).toBeDefined();

    // Verify public key is valid base64url and decodes to 32 bytes
    const pubBytes = Buffer.from(data.x25519Public, 'base64url');
    expect(pubBytes.length).toBe(32);
  });

  it('rejects missing name', async () => {
    const res = await app.request('/api/tenants', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400);
  });
});

describe('GET /api/tenants/:id', () => {
  it('returns tenant with public key', async () => {
    // Create a tenant first
    const createRes = await app.request('/api/tenants', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Get Test' }),
    });
    const created = await createRes.json();

    const res = await app.request(`/api/tenants/${created.id}`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.name).toBe('Get Test');
    expect(data.x25519Public).toBe(created.x25519Public);
  });

  it('returns 404 for unknown tenant', async () => {
    const res = await app.request('/api/tenants/00000000-0000-0000-0000-000000000000');
    expect(res.status).toBe(404);
  });
});
