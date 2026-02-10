import { ed25519, signatures, x25519 } from '@clavum/crypto';
import { Hono } from 'hono';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db.js';
import { authMiddleware } from '../../src/middleware/auth.js';

let agentId: string;
let agentEd25519Priv: Uint8Array;
let agentEd25519Pub: Uint8Array;

// Create a test app with auth middleware
const testApp = new Hono();
testApp.use('/api/test/*', authMiddleware);
testApp.post('/api/test/echo', (c) => {
  const agent = c.get('agent');
  return c.json({ agentId: agent.id, ok: true });
});

function signRequest(method: string, path: string, body: string, timestampOverride?: string) {
  const timestamp = timestampOverride ?? Date.now().toString();
  const bodyBytes = new TextEncoder().encode(body);
  const sig = signatures.signRequest(agentEd25519Priv, timestamp, method, path, bodyBytes);
  return {
    timestamp,
    signature: Buffer.from(sig).toString('base64url'),
  };
}

beforeAll(async () => {
  await prisma.usedNonce.deleteMany();
  await prisma.pairingInvitation.deleteMany();
  await prisma.agent.deleteMany();
  await prisma.phone.deleteMany();
  await prisma.secretMetadata.deleteMany();
  await prisma.tenant.deleteMany();

  // Create tenant + agent
  const serverKeys = x25519.generateKeypair();
  const tenant = await prisma.tenant.create({
    data: {
      name: 'Auth Test Tenant',
      x25519Private: Buffer.from(serverKeys.privateKey),
      x25519Public: Buffer.from(serverKeys.publicKey),
    },
  });

  const agentX25519Keys = x25519.generateKeypair();
  const agentEdKeys = ed25519.generateKeypair();
  agentEd25519Priv = agentEdKeys.privateKey;
  agentEd25519Pub = agentEdKeys.publicKey;

  const agent = await prisma.agent.create({
    data: {
      tenantId: tenant.id,
      name: 'test-agent',
      x25519Public: Buffer.from(agentX25519Keys.publicKey),
      ed25519Public: Buffer.from(agentEdKeys.publicKey),
    },
  });
  agentId = agent.id;
});

beforeEach(async () => {
  await prisma.usedNonce.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('auth middleware', () => {
  it('valid signature → passes, agent set on context', async () => {
    const body = JSON.stringify({ hello: 'world' });
    const { timestamp, signature } = signRequest('POST', '/api/test/echo', body);

    const res = await testApp.request('/api/test/echo', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Agent-Id': agentId,
        'X-Timestamp': timestamp,
        'X-Signature': signature,
      },
      body,
    });

    expect(res.status).toBe(200);
    const data = (await res.json()) as { agentId: string; ok: boolean };
    expect(data.agentId).toBe(agentId);
    expect(data.ok).toBe(true);
  });

  it('invalid signature → 401', async () => {
    const body = JSON.stringify({ hello: 'world' });
    const { timestamp } = signRequest('POST', '/api/test/echo', body);

    const res = await testApp.request('/api/test/echo', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Agent-Id': agentId,
        'X-Timestamp': timestamp,
        'X-Signature': 'invalid-signature-data',
      },
      body,
    });

    expect(res.status).toBe(401);
  });

  it('expired timestamp (>60s) → 401', async () => {
    const body = JSON.stringify({ hello: 'world' });
    const oldTimestamp = String(Date.now() - 120000);
    const { signature } = signRequest('POST', '/api/test/echo', body, oldTimestamp);

    const res = await testApp.request('/api/test/echo', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Agent-Id': agentId,
        'X-Timestamp': oldTimestamp,
        'X-Signature': signature,
      },
      body,
    });

    expect(res.status).toBe(401);
  });

  it('missing headers → 401', async () => {
    const res = await testApp.request('/api/test/echo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });

    expect(res.status).toBe(401);
  });

  it('unknown agent_id → 401', async () => {
    const body = '{}';
    const { timestamp, signature } = signRequest('POST', '/api/test/echo', body);

    const res = await testApp.request('/api/test/echo', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Agent-Id': '00000000-0000-0000-0000-000000000000',
        'X-Timestamp': timestamp,
        'X-Signature': signature,
      },
      body,
    });

    expect(res.status).toBe(401);
  });

  it('replayed nonce → 409', async () => {
    const body = JSON.stringify({ test: 'replay' });
    const { timestamp, signature } = signRequest('POST', '/api/test/echo', body);

    const headers = {
      'Content-Type': 'application/json',
      'X-Agent-Id': agentId,
      'X-Timestamp': timestamp,
      'X-Signature': signature,
    };

    // First request succeeds
    const res1 = await testApp.request('/api/test/echo', {
      method: 'POST',
      headers,
      body,
    });
    expect(res1.status).toBe(200);

    // Same request replayed → 409
    const res2 = await testApp.request('/api/test/echo', {
      method: 'POST',
      headers,
      body,
    });
    expect(res2.status).toBe(409);
  });
});
