/**
 * Audit logging service.
 *
 * Records all secret access attempts with cryptographic proof
 * and reason tracking for compliance.
 */

import type { AuditResult, Tier } from '@prisma/client';
import { prisma } from '../db.js';

export interface CreateAuditEntryParams {
  agentId: string;
  secretId: string;
  reason: string;
  tier: Tier;
  result: AuditResult;
  latencyMs?: number;
  proof?: Uint8Array;
}

export interface QueryAuditParams {
  agentId?: string;
  secretId?: string;
  from?: Date;
  to?: Date;
  limit?: number;
}

/**
 * Create an audit log entry for a secret access attempt.
 */
export async function createEntry(params: CreateAuditEntryParams): Promise<string> {
  const entry = await prisma.auditLog.create({
    data: {
      agentId: params.agentId,
      secretId: params.secretId,
      reason: params.reason,
      tier: params.tier,
      result: params.result,
      latencyMs: params.latencyMs ?? null,
      proof: params.proof ? Buffer.from(params.proof) : null,
    },
  });
  return entry.id;
}

/**
 * Query audit log entries with optional filters.
 */
export async function queryEntries(params: QueryAuditParams) {
  const where: Record<string, unknown> = {};

  if (params.agentId) where.agentId = params.agentId;
  if (params.secretId) where.secretId = params.secretId;

  if (params.from || params.to) {
    const createdAt: Record<string, Date> = {};
    if (params.from) createdAt.gte = params.from;
    if (params.to) createdAt.lte = params.to;
    where.createdAt = createdAt;
  }

  return prisma.auditLog.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: params.limit ?? 50,
  });
}
