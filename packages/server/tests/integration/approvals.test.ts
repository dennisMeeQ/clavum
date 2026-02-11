import { ed25519, signatures, toBase64Url, x25519 } from '@clavum/crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db.js';
import { createApproval } from '../../src/services/approval.js';

let tenantId: string;
let phoneId: string;
let phoneEdPriv: Uint8Array;
let secretId: string;

// Second tenant for isolation
let otherTenantId: string;
let otherPhoneId: string;
let otherPhoneEdPriv: Uint8Array;

function phoneSignedHeaders(
  pId: string,
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
    'X-Phone-Id': pId,
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
      name: 'Approvals Route Test',
      x25519Private: Buffer.from(sKeys.privateKey),
      x25519Public: Buffer.from(sKeys.publicKey),
    },
  });
  tenantId = tenant.id;

  const phoneEdKeys = ed25519.generateKeypair();
  phoneEdPriv = phoneEdKeys.privateKey;
  const phoneXKeys = x25519.generateKeypair();
  const phone = await prisma.phone.create({
    data: {
      tenantId,
      name: 'route-test-phone',
      x25519Public: Buffer.from(phoneXKeys.publicKey),
      ed25519Public: Buffer.from(phoneEdKeys.publicKey),
    },
  });
  phoneId = phone.id;

  const agentEdKeys = ed25519.generateKeypair();
  const agentXKeys = x25519.generateKeypair();
  const agent = await prisma.agent.create({
    data: {
      tenantId,
      name: 'route-test-agent',
      x25519Public: Buffer.from(agentXKeys.publicKey),
      ed25519Public: Buffer.from(agentEdKeys.publicKey),
    },
  });

  const secret = await prisma.secretMetadata.create({
    data: { tenantId, agentId: agent.id, name: 'route-yellow', tier: 'yellow' },
  });
  secretId = secret.id;

  // Other tenant
  const sKeys2 = x25519.generateKeypair();
  const tenant2 = await prisma.tenant.create({
    data: {
      name: 'Other Route Tenant',
      x25519Private: Buffer.from(sKeys2.privateKey),
      x25519Public: Buffer.from(sKeys2.publicKey),
    },
  });
  otherTenantId = tenant2.id;

  const otherEdKeys = ed25519.generateKeypair();
  otherPhoneEdPriv = otherEdKeys.privateKey;
  const otherXKeys = x25519.generateKeypair();
  const otherPhone = await prisma.phone.create({
    data: {
      tenantId: otherTenantId,
      name: 'other-route-phone',
      x25519Public: Buffer.from(otherXKeys.publicKey),
      ed25519Public: Buffer.from(otherEdKeys.publicKey),
    },
  });
  otherPhoneId = otherPhone.id;
});

beforeEach(async () => {
  await prisma.approvalRequest.deleteMany();
  await prisma.usedNonce.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('GET /api/approvals/pending', () => {
  it('should return pending approvals for the phone tenant', async () => {
    await createApproval({ secretId, phoneId, reason: 'test reason' });

    const path = '/api/approvals/pending';
    const headers = phoneSignedHeaders(phoneId, phoneEdPriv, 'GET', path, '');
    const res = await app.request(path, { method: 'GET', headers });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.approvals).toHaveLength(1);
    expect(json.approvals[0].reason).toBe('test reason');
    expect(json.approvals[0].challenge).toBeDefined();
    expect(json.approvals[0].secret_id).toBe(secretId);
  });

  it('should not return other tenant approvals', async () => {
    await createApproval({ secretId, phoneId, reason: 'my tenant only' });

    const path = '/api/approvals/pending';
    const headers = phoneSignedHeaders(otherPhoneId, otherPhoneEdPriv, 'GET', path, '');
    const res = await app.request(path, { method: 'GET', headers });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.approvals).toHaveLength(0);
  });

  it('should exclude expired approvals', async () => {
    await createApproval({ secretId, phoneId, reason: 'expired', timeoutMs: 1 });
    await new Promise((r) => setTimeout(r, 5));
    await createApproval({ secretId, phoneId, reason: 'fresh' });

    const path = '/api/approvals/pending';
    const headers = phoneSignedHeaders(phoneId, phoneEdPriv, 'GET', path, '');
    const res = await app.request(path, { method: 'GET', headers });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.approvals).toHaveLength(1);
    expect(json.approvals[0].reason).toBe('fresh');
  });
});

describe('POST /api/approvals/:id/approve', () => {
  it('should approve with valid signature', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'approve via route' });
    const sig = signatures.signApproval(phoneEdPriv, approval.challenge);

    const path = `/api/approvals/${approval.id}/approve`;
    const body = JSON.stringify({ signature: toBase64Url(sig) });
    const headers = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.status).toBe('approved');
    expect(json.responded_at).toBeDefined();
  });

  it('should return 400 for invalid signature', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'bad sig route' });
    const wrongKeys = ed25519.generateKeypair();
    const badSig = signatures.signApproval(wrongKeys.privateKey, approval.challenge);

    const path = `/api/approvals/${approval.id}/approve`;
    const body = JSON.stringify({ signature: toBase64Url(badSig) });
    const headers = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });

    expect(res.status).toBe(400);
  });

  it('should return 400 for missing signature field', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'no sig' });

    const path = `/api/approvals/${approval.id}/approve`;
    const body = JSON.stringify({});
    const headers = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });

    expect(res.status).toBe(400);
  });

  it('should return 404 for non-existent approval', async () => {
    const path = '/api/approvals/non-existent/approve';
    const body = JSON.stringify({ signature: 'AAAA' });
    const headers = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });

    expect(res.status).toBe(404);
  });

  it('should return 409 for already resolved approval', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'double' });
    const sig = signatures.signApproval(phoneEdPriv, approval.challenge);

    // First approve
    const path = `/api/approvals/${approval.id}/approve`;
    const body = JSON.stringify({ signature: toBase64Url(sig) });
    const headers1 = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    await app.request(path, { method: 'POST', headers: headers1, body });

    // Second approve
    const headers2 = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers: headers2, body });

    expect(res.status).toBe(409);
  });

  it('should return 410 for expired approval', async () => {
    const approval = await createApproval({
      secretId,
      phoneId,
      reason: 'too late',
      timeoutMs: 1,
    });
    await new Promise((r) => setTimeout(r, 5));

    const sig = signatures.signApproval(phoneEdPriv, approval.challenge);
    const path = `/api/approvals/${approval.id}/approve`;
    const body = JSON.stringify({ signature: toBase64Url(sig) });
    const headers = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });

    expect(res.status).toBe(410);
  });
});

describe('POST /api/approvals/:id/reject', () => {
  it('should reject a pending approval', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'reject route' });

    const path = `/api/approvals/${approval.id}/reject`;
    const body = '';
    const headers = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.status).toBe('denied');
  });

  it('should return 404 for non-existent approval', async () => {
    const path = '/api/approvals/non-existent/reject';
    const body = '';
    const headers = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers, body });

    expect(res.status).toBe(404);
  });

  it('should return 409 for already resolved approval', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'double reject' });

    const path = `/api/approvals/${approval.id}/reject`;
    const body = '';
    const headers1 = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    await app.request(path, { method: 'POST', headers: headers1, body });

    const headers2 = phoneSignedHeaders(phoneId, phoneEdPriv, 'POST', path, body);
    const res = await app.request(path, { method: 'POST', headers: headers2, body });

    expect(res.status).toBe(409);
  });
});
