import { fingerprintToEmoji, kdf, x25519 } from '@clavum/crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db.js';

let tenantId: string;
let serverX25519Pub: string;

async function createInvitation(type = 'phone') {
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
    body: JSON.stringify({ name: 'Phone Pairing Test' }),
  });
  const data = (await res.json()) as { id: string; x25519Public: string };
  tenantId = data.id;
  serverX25519Pub = data.x25519Public;
});

beforeEach(async () => {
  await prisma.pairingInvitation.deleteMany();
  await prisma.phone.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('POST /api/pair/phone', () => {
  it('registers phone with valid token', async () => {
    const { token } = await createInvitation();
    const phoneKeys = x25519.generateKeypair();
    const { ed25519 } = await import('@clavum/crypto');
    const phoneSignKeys = ed25519.generateKeypair();

    const res = await app.request('/api/pair/phone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        x25519_pub: Buffer.from(phoneKeys.publicKey).toString('base64url'),
        ed25519_pub: Buffer.from(phoneSignKeys.publicKey).toString('base64url'),
        name: 'Dennis iPhone',
      }),
    });

    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      phoneId: string;
      serverX25519Pub: string;
      fingerprint: string;
    };
    expect(data.phoneId).toBeDefined();
    expect(data.serverX25519Pub).toBe(serverX25519Pub);
    expect(data.fingerprint).toBeTruthy();
  });

  it('uses default name when not provided', async () => {
    const { token } = await createInvitation();
    const phoneKeys = x25519.generateKeypair();
    const { ed25519 } = await import('@clavum/crypto');
    const phoneSignKeys = ed25519.generateKeypair();

    const res = await app.request('/api/pair/phone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        x25519_pub: Buffer.from(phoneKeys.publicKey).toString('base64url'),
        ed25519_pub: Buffer.from(phoneSignKeys.publicKey).toString('base64url'),
      }),
    });

    expect(res.status).toBe(200);
    const data = (await res.json()) as { phoneId: string };
    expect(data.phoneId).toBeDefined();

    // Verify default name in DB
    const phone = await prisma.phone.findUnique({
      where: { id: data.phoneId },
    });
    expect(phone?.name).toBe('Phone');
  });

  it('rejects already-used token', async () => {
    const { token } = await createInvitation();
    const { ed25519 } = await import('@clavum/crypto');
    const phoneKeys = x25519.generateKeypair();
    const phoneSignKeys = ed25519.generateKeypair();

    const body = {
      token,
      x25519_pub: Buffer.from(phoneKeys.publicKey).toString('base64url'),
      ed25519_pub: Buffer.from(phoneSignKeys.publicKey).toString('base64url'),
    };

    await app.request('/api/pair/phone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const res2 = await app.request('/api/pair/phone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    expect(res2.status).toBe(400);
  });

  it('rejects expired token', async () => {
    const { token } = await createInvitation();
    await prisma.pairingInvitation.update({
      where: { token },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    const phoneKeys = x25519.generateKeypair();
    const { ed25519 } = await import('@clavum/crypto');
    const phoneSignKeys = ed25519.generateKeypair();

    const res = await app.request('/api/pair/phone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        x25519_pub: Buffer.from(phoneKeys.publicKey).toString('base64url'),
        ed25519_pub: Buffer.from(phoneSignKeys.publicKey).toString('base64url'),
      }),
    });
    expect(res.status).toBe(400);
  });

  it('rejects invalid token', async () => {
    const phoneKeys = x25519.generateKeypair();
    const { ed25519 } = await import('@clavum/crypto');
    const phoneSignKeys = ed25519.generateKeypair();

    const res = await app.request('/api/pair/phone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: 'nonexistent',
        x25519_pub: Buffer.from(phoneKeys.publicKey).toString('base64url'),
        ed25519_pub: Buffer.from(phoneSignKeys.publicKey).toString('base64url'),
      }),
    });
    expect(res.status).toBe(404);
  });

  it('fingerprint matches local calculation', async () => {
    const { token } = await createInvitation();
    const phoneKeys = x25519.generateKeypair();
    const { ed25519 } = await import('@clavum/crypto');
    const phoneSignKeys = ed25519.generateKeypair();

    const res = await app.request('/api/pair/phone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        x25519_pub: Buffer.from(phoneKeys.publicKey).toString('base64url'),
        ed25519_pub: Buffer.from(phoneSignKeys.publicKey).toString('base64url'),
        name: 'Test Phone',
      }),
    });

    const data = (await res.json()) as {
      serverX25519Pub: string;
      fingerprint: string;
    };

    const serverPubBytes = new Uint8Array(Buffer.from(data.serverX25519Pub, 'base64url'));
    const sharedSecret = x25519.sharedSecret(phoneKeys.privateKey, serverPubBytes);
    const fpBytes = kdf.deriveFingerprint(sharedSecret);
    const expectedEmoji = fingerprintToEmoji(fpBytes);

    expect(data.fingerprint).toBe(expectedEmoji);
  });
});
