import { fingerprintToEmoji, kdf, x25519 } from '@clavum/crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db.js';

let tenantId: string;
let serverX25519Pub: string;

async function createInvitation(type = 'agent') {
  const res = await app.request('/api/pair/invite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenantId, type }),
  });
  return (await res.json()) as { token: string };
}

beforeAll(async () => {
  await prisma.pairingInvitation.deleteMany();
  await prisma.agent.deleteMany();
  await prisma.phone.deleteMany();
  await prisma.secretMetadata.deleteMany();
  await prisma.tenant.deleteMany();

  const res = await app.request('/api/tenants', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Agent Pairing Test' }),
  });
  const data = (await res.json()) as { id: string; x25519Public: string };
  tenantId = data.id;
  serverX25519Pub = data.x25519Public;
});

beforeEach(async () => {
  await prisma.pairingInvitation.deleteMany();
  await prisma.agent.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('POST /api/pair/agent', () => {
  it('registers agent with valid token', async () => {
    const { token } = await createInvitation();
    const agentKeys = x25519.generateKeypair();
    const { ed25519 } = await import('@clavum/crypto');
    const agentSignKeys = ed25519.generateKeypair();

    const res = await app.request('/api/pair/agent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        x25519_pub: Buffer.from(agentKeys.publicKey).toString('base64url'),
        ed25519_pub: Buffer.from(agentSignKeys.publicKey).toString('base64url'),
        name: 'test-agent',
      }),
    });

    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      agentId: string;
      serverX25519Pub: string;
      fingerprint: string;
    };
    expect(data.agentId).toBeDefined();
    expect(data.serverX25519Pub).toBe(serverX25519Pub);
    expect(data.fingerprint).toBeDefined();
    // Fingerprint is 4 emoji (some may have variation selectors)
    expect(data.fingerprint).toBeTruthy();
  });

  it('invalidates token after use', async () => {
    const { token } = await createInvitation();
    const { ed25519 } = await import('@clavum/crypto');
    const agentKeys = x25519.generateKeypair();
    const agentSignKeys = ed25519.generateKeypair();

    const body = {
      token,
      x25519_pub: Buffer.from(agentKeys.publicKey).toString('base64url'),
      ed25519_pub: Buffer.from(agentSignKeys.publicKey).toString('base64url'),
      name: 'test-agent',
    };

    // First use succeeds
    const res1 = await app.request('/api/pair/agent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    expect(res1.status).toBe(200);

    // Second use fails
    const res2 = await app.request('/api/pair/agent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, name: 'test-agent-2' }),
    });
    expect(res2.status).toBe(400);
    const err = (await res2.json()) as { error: string };
    expect(err.error).toContain('already used');
  });

  it('rejects expired token', async () => {
    const { token } = await createInvitation();
    const { ed25519 } = await import('@clavum/crypto');

    // Manually expire the token
    await prisma.pairingInvitation.update({
      where: { token },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    const agentKeys = x25519.generateKeypair();
    const agentSignKeys = ed25519.generateKeypair();

    const res = await app.request('/api/pair/agent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        x25519_pub: Buffer.from(agentKeys.publicKey).toString('base64url'),
        ed25519_pub: Buffer.from(agentSignKeys.publicKey).toString('base64url'),
        name: 'test-agent',
      }),
    });
    expect(res.status).toBe(400);
    const err = (await res.json()) as { error: string };
    expect(err.error).toContain('expired');
  });

  it('rejects invalid token', async () => {
    const { ed25519 } = await import('@clavum/crypto');
    const agentKeys = x25519.generateKeypair();
    const agentSignKeys = ed25519.generateKeypair();

    const res = await app.request('/api/pair/agent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: 'nonexistent-token',
        x25519_pub: Buffer.from(agentKeys.publicKey).toString('base64url'),
        ed25519_pub: Buffer.from(agentSignKeys.publicKey).toString('base64url'),
        name: 'test-agent',
      }),
    });
    expect(res.status).toBe(404);
  });

  it('rejects missing fields', async () => {
    const { token } = await createInvitation();

    const res = await app.request('/api/pair/agent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    expect(res.status).toBe(400);
  });

  it('fingerprint matches local calculation', async () => {
    const { token } = await createInvitation();
    const { ed25519 } = await import('@clavum/crypto');
    const agentKeys = x25519.generateKeypair();
    const agentSignKeys = ed25519.generateKeypair();

    const res = await app.request('/api/pair/agent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        x25519_pub: Buffer.from(agentKeys.publicKey).toString('base64url'),
        ed25519_pub: Buffer.from(agentSignKeys.publicKey).toString('base64url'),
        name: 'test-agent',
      }),
    });

    const data = (await res.json()) as {
      serverX25519Pub: string;
      fingerprint: string;
    };

    // Derive fingerprint locally
    const serverPubBytes = new Uint8Array(Buffer.from(data.serverX25519Pub, 'base64url'));
    const sharedSecret = x25519.sharedSecret(agentKeys.privateKey, serverPubBytes);
    const fpBytes = kdf.deriveFingerprint(sharedSecret);
    const expectedEmoji = fingerprintToEmoji(fpBytes);

    expect(data.fingerprint).toBe(expectedEmoji);
  });
});
