/**
 * Approval service for yellow-tier secret retrieval.
 *
 * Manages the lifecycle of phone approval requests:
 * create → pending → approved/denied/expired.
 */

import { signatures } from '@clavum/crypto';
import type { ApprovalRequest, ApprovalStatus } from '@prisma/client';
import { prisma } from '../db.js';

/** Default approval timeout: 5 minutes. */
const DEFAULT_TIMEOUT_MS = 300_000;

export interface CreateApprovalParams {
  secretId: string;
  phoneId: string;
  reason: string;
  timeoutMs?: number;
}

export interface ApprovalResult {
  id: string;
  status: ApprovalStatus;
  challenge: Uint8Array;
  expiresAt: Date;
}

/**
 * Create a new approval request with a context-bound challenge.
 */
export async function createApproval(params: CreateApprovalParams): Promise<ApprovalResult> {
  const timeoutMs = params.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const challenge = signatures.buildChallenge(params.secretId, params.reason);
  const expiresAt = new Date(Date.now() + timeoutMs);

  const record = await prisma.approvalRequest.create({
    data: {
      phoneId: params.phoneId,
      secretId: params.secretId,
      reason: params.reason,
      challenge: Buffer.from(challenge),
      status: 'pending',
      expiresAt,
    },
  });

  return {
    id: record.id,
    status: record.status,
    challenge: new Uint8Array(record.challenge),
    expiresAt: record.expiresAt,
  };
}

/**
 * Approve an approval request by verifying the phone's Ed25519 signature.
 *
 * @throws Error if approval not found, not pending, expired, or signature invalid.
 */
export async function approveRequest(
  id: string,
  signature: Uint8Array,
  phonePub: Uint8Array,
): Promise<ApprovalRequest> {
  const approval = await prisma.approvalRequest.findUnique({ where: { id } });

  if (!approval) {
    throw new ApprovalError('approval_not_found', 'Approval request not found');
  }

  if (approval.status !== 'pending') {
    throw new ApprovalError('already_resolved', `Approval already ${approval.status}`);
  }

  // Lazy expiry check
  if (approval.expiresAt <= new Date()) {
    await prisma.approvalRequest.update({
      where: { id },
      data: { status: 'expired', respondedAt: new Date() },
    });
    throw new ApprovalError('expired', 'Approval request has expired');
  }

  // Verify Ed25519 signature over the challenge
  const challenge = new Uint8Array(approval.challenge);
  const valid = signatures.verifyApproval(phonePub, challenge, signature);

  if (!valid) {
    throw new ApprovalError('invalid_signature', 'Approval signature verification failed');
  }

  return prisma.approvalRequest.update({
    where: { id },
    data: {
      status: 'approved',
      approvalSig: Buffer.from(signature),
      respondedAt: new Date(),
    },
  });
}

/**
 * Reject an approval request.
 *
 * @throws Error if approval not found or not pending.
 */
export async function rejectRequest(id: string): Promise<ApprovalRequest> {
  const approval = await prisma.approvalRequest.findUnique({ where: { id } });

  if (!approval) {
    throw new ApprovalError('approval_not_found', 'Approval request not found');
  }

  if (approval.status !== 'pending') {
    throw new ApprovalError('already_resolved', `Approval already ${approval.status}`);
  }

  return prisma.approvalRequest.update({
    where: { id },
    data: {
      status: 'denied',
      respondedAt: new Date(),
    },
  });
}

/**
 * Get pending approval requests for a tenant.
 * Lazy-expires stale ones before returning.
 */
export async function getPending(tenantId: string): Promise<ApprovalRequest[]> {
  // First, bulk-expire stale approvals for this tenant's phones
  await expireStaleForTenant(tenantId);

  return prisma.approvalRequest.findMany({
    where: {
      status: 'pending',
      phone: { tenantId },
    },
    include: {
      phone: { select: { tenantId: true } },
    },
    orderBy: { createdAt: 'asc' },
  });
}

/**
 * Get the current status and metadata of an approval request.
 * Performs lazy expiry check.
 */
export async function getStatus(approvalId: string): Promise<ApprovalRequest | null> {
  const approval = await prisma.approvalRequest.findUnique({ where: { id: approvalId } });

  if (!approval) {
    return null;
  }

  // Lazy expiry
  if (approval.status === 'pending' && approval.expiresAt <= new Date()) {
    return prisma.approvalRequest.update({
      where: { id: approvalId },
      data: { status: 'expired', respondedAt: new Date() },
    });
  }

  return approval;
}

/**
 * Bulk mark all expired pending approvals.
 * Returns the number of records updated.
 */
export async function expireStale(): Promise<number> {
  const result = await prisma.approvalRequest.updateMany({
    where: {
      status: 'pending',
      expiresAt: { lt: new Date() },
    },
    data: {
      status: 'expired',
      respondedAt: new Date(),
    },
  });
  return result.count;
}

/**
 * Expire stale approvals for a specific tenant's phones.
 */
async function expireStaleForTenant(tenantId: string): Promise<number> {
  // Get phone IDs for this tenant
  const phones = await prisma.phone.findMany({
    where: { tenantId },
    select: { id: true },
  });
  const phoneIds = phones.map((p) => p.id);

  if (phoneIds.length === 0) return 0;

  const result = await prisma.approvalRequest.updateMany({
    where: {
      status: 'pending',
      phoneId: { in: phoneIds },
      expiresAt: { lt: new Date() },
    },
    data: {
      status: 'expired',
      respondedAt: new Date(),
    },
  });
  return result.count;
}

/**
 * Custom error class for approval operations.
 */
export class ApprovalError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApprovalError';
  }
}
