import { ed25519, signatures } from '@clavum/crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db.js';
import {
  ApprovalError,
  approveRequest,
  createApproval,
  expireStale,
  getPending,
  getStatus,
  rejectRequest,
} from '../../src/services/approval.js';

let tenantId: string;
let phoneId: string;
let phonePub: Uint8Array;
let phonePriv: Uint8Array;
let secretId: string;

// Second tenant for isolation tests
let otherTenantId: string;
let _otherPhoneId: string;

beforeAll(async () => {
  // Clean up
  await prisma.auditLog.deleteMany();
  await prisma.approvalRequest.deleteMany();
  await prisma.secretMetadata.deleteMany();
  await prisma.usedNonce.deleteMany();
  await prisma.pairingInvitation.deleteMany();
  await prisma.agent.deleteMany();
  await prisma.phone.deleteMany();
  await prisma.tenant.deleteMany();

  const { x25519 } = await import('@clavum/crypto');

  // Create tenant + phone + agent + secret
  const sKeys = x25519.generateKeypair();
  const tenant = await prisma.tenant.create({
    data: {
      name: 'Approval Test Tenant',
      x25519Private: Buffer.from(sKeys.privateKey),
      x25519Public: Buffer.from(sKeys.publicKey),
    },
  });
  tenantId = tenant.id;

  const phoneKeys = ed25519.generateKeypair();
  phonePriv = phoneKeys.privateKey;
  phonePub = phoneKeys.publicKey;
  const phoneX = x25519.generateKeypair();
  const phone = await prisma.phone.create({
    data: {
      tenantId,
      name: 'test-phone',
      x25519Public: Buffer.from(phoneX.publicKey),
      ed25519Public: Buffer.from(phonePub),
    },
  });
  phoneId = phone.id;

  const agentKeys = ed25519.generateKeypair();
  const agentX = x25519.generateKeypair();
  const agent = await prisma.agent.create({
    data: {
      tenantId,
      name: 'test-agent',
      x25519Public: Buffer.from(agentX.publicKey),
      ed25519Public: Buffer.from(agentKeys.publicKey),
    },
  });

  const secret = await prisma.secretMetadata.create({
    data: {
      tenantId,
      agentId: agent.id,
      name: 'yellow-secret',
      tier: 'yellow',
    },
  });
  secretId = secret.id;

  // Other tenant for isolation
  const sKeys2 = x25519.generateKeypair();
  const tenant2 = await prisma.tenant.create({
    data: {
      name: 'Other Tenant',
      x25519Private: Buffer.from(sKeys2.privateKey),
      x25519Public: Buffer.from(sKeys2.publicKey),
    },
  });
  otherTenantId = tenant2.id;

  const otherPhoneKeys = ed25519.generateKeypair();
  const otherPhoneX = x25519.generateKeypair();
  const otherPhone = await prisma.phone.create({
    data: {
      tenantId: otherTenantId,
      name: 'other-phone',
      x25519Public: Buffer.from(otherPhoneX.publicKey),
      ed25519Public: Buffer.from(otherPhoneKeys.publicKey),
    },
  });
  _otherPhoneId = otherPhone.id;
});

beforeEach(async () => {
  await prisma.approvalRequest.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('createApproval', () => {
  it('should create a pending approval with valid challenge', async () => {
    const result = await createApproval({
      secretId,
      phoneId,
      reason: 'need access',
    });

    expect(result.status).toBe('pending');
    expect(result.id).toBeDefined();
    expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
    expect(result.challenge.length).toBeGreaterThan(0);

    // Verify challenge is context-bound (contains secretId bytes + reason hash)
    const expectedChallenge = signatures.buildChallenge(
      secretId,
      'need access',
      result.challenge.slice(0, 32),
    );
    expect(Buffer.from(result.challenge).toString('hex')).toBe(
      Buffer.from(expectedChallenge).toString('hex'),
    );
  });

  it('should respect custom timeout', async () => {
    const before = Date.now();
    const result = await createApproval({
      secretId,
      phoneId,
      reason: 'quick',
      timeoutMs: 10_000,
    });

    const expiryMs = result.expiresAt.getTime() - before;
    expect(expiryMs).toBeGreaterThanOrEqual(9_000);
    expect(expiryMs).toBeLessThanOrEqual(11_000);
  });
});

describe('approveRequest', () => {
  it('should approve with valid signature and store sig', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'approve me' });

    const sig = signatures.signApproval(phonePriv, approval.challenge);
    const result = await approveRequest(approval.id, sig, phonePub);

    expect(result.status).toBe('approved');
    expect(result.approvalSig).not.toBeNull();
    expect(result.respondedAt).not.toBeNull();
  });

  it('should reject invalid signature', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'bad sig' });

    const wrongKeys = ed25519.generateKeypair();
    const badSig = signatures.signApproval(wrongKeys.privateKey, approval.challenge);

    await expect(approveRequest(approval.id, badSig, phonePub)).rejects.toThrow(ApprovalError);

    // Should still be pending
    const status = await getStatus(approval.id);
    expect(status?.status).toBe('pending');
  });

  it('should throw on non-existent approval', async () => {
    const fakeSig = new Uint8Array(64);
    await expect(approveRequest('non-existent-id', fakeSig, phonePub)).rejects.toThrow(
      'Approval request not found',
    );
  });

  it('should throw on already approved request', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'double approve' });
    const sig = signatures.signApproval(phonePriv, approval.challenge);
    await approveRequest(approval.id, sig, phonePub);

    await expect(approveRequest(approval.id, sig, phonePub)).rejects.toThrow('already approved');
  });

  it('should throw on already denied request', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'deny then approve' });
    await rejectRequest(approval.id);

    const sig = signatures.signApproval(phonePriv, approval.challenge);
    await expect(approveRequest(approval.id, sig, phonePub)).rejects.toThrow('already denied');
  });

  it('should throw on expired approval', async () => {
    const approval = await createApproval({
      secretId,
      phoneId,
      reason: 'too slow',
      timeoutMs: 1, // 1ms timeout — will expire immediately
    });

    // Wait a tick for expiry
    await new Promise((r) => setTimeout(r, 5));

    const sig = signatures.signApproval(phonePriv, approval.challenge);
    await expect(approveRequest(approval.id, sig, phonePub)).rejects.toThrow('expired');

    // Verify it was marked expired in DB
    const status = await getStatus(approval.id);
    expect(status?.status).toBe('expired');
  });
});

describe('rejectRequest', () => {
  it('should mark as denied with respondedAt', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'deny me' });
    const result = await rejectRequest(approval.id);

    expect(result.status).toBe('denied');
    expect(result.respondedAt).not.toBeNull();
  });

  it('should throw on non-existent approval', async () => {
    await expect(rejectRequest('non-existent-id')).rejects.toThrow('not found');
  });

  it('should throw on already resolved approval', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'reject twice' });
    await rejectRequest(approval.id);
    await expect(rejectRequest(approval.id)).rejects.toThrow('already denied');
  });
});

describe('getPending', () => {
  it('should return pending approvals for a tenant', async () => {
    await createApproval({ secretId, phoneId, reason: 'pending 1' });
    await createApproval({ secretId, phoneId, reason: 'pending 2' });

    const pending = await getPending(tenantId);
    expect(pending).toHaveLength(2);
  });

  it('should exclude resolved approvals', async () => {
    const a1 = await createApproval({ secretId, phoneId, reason: 'will approve' });
    await createApproval({ secretId, phoneId, reason: 'still pending' });
    const a3 = await createApproval({ secretId, phoneId, reason: 'will deny' });

    const sig = signatures.signApproval(phonePriv, a1.challenge);
    await approveRequest(a1.id, sig, phonePub);
    await rejectRequest(a3.id);

    const pending = await getPending(tenantId);
    expect(pending).toHaveLength(1);
    expect(pending[0].reason).toBe('still pending');
  });

  it('should lazy-expire stale approvals', async () => {
    await createApproval({ secretId, phoneId, reason: 'will expire', timeoutMs: 1 });
    await new Promise((r) => setTimeout(r, 5));
    await createApproval({ secretId, phoneId, reason: 'still valid' });

    const pending = await getPending(tenantId);
    expect(pending).toHaveLength(1);
    expect(pending[0].reason).toBe('still valid');
  });

  it('should not return other tenant approvals', async () => {
    await createApproval({ secretId, phoneId, reason: 'my tenant' });

    const otherPending = await getPending(otherTenantId);
    expect(otherPending).toHaveLength(0);
  });
});

describe('getStatus', () => {
  it('should return current status', async () => {
    const approval = await createApproval({ secretId, phoneId, reason: 'check status' });
    const status = await getStatus(approval.id);

    expect(status).not.toBeNull();
    expect(status?.status).toBe('pending');
    expect(status?.challenge).toBeDefined();
  });

  it('should lazy-expire on status check', async () => {
    const approval = await createApproval({
      secretId,
      phoneId,
      reason: 'will auto expire',
      timeoutMs: 1,
    });
    await new Promise((r) => setTimeout(r, 5));

    const status = await getStatus(approval.id);
    expect(status?.status).toBe('expired');
    expect(status?.respondedAt).not.toBeNull();
  });

  it('should return null for non-existent approval', async () => {
    const status = await getStatus('does-not-exist');
    expect(status).toBeNull();
  });
});

describe('expireStale', () => {
  it('should bulk expire all stale pending approvals', async () => {
    await createApproval({ secretId, phoneId, reason: 'stale 1', timeoutMs: 1 });
    await createApproval({ secretId, phoneId, reason: 'stale 2', timeoutMs: 1 });
    await new Promise((r) => setTimeout(r, 5));
    await createApproval({ secretId, phoneId, reason: 'fresh' });

    const count = await expireStale();
    expect(count).toBe(2);

    // Fresh one is still pending
    const all = await prisma.approvalRequest.findMany({ where: { status: 'pending' } });
    expect(all).toHaveLength(1);
    expect(all[0].reason).toBe('fresh');
  });
});
