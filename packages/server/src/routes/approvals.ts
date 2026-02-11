/**
 * Approval API routes for phone-based yellow tier approval.
 *
 * All routes require phone authentication (Ed25519 signed requests).
 */

import { fromBase64Url } from '@clavum/crypto';
import { Hono } from 'hono';
import { phoneAuthMiddleware } from '../middleware/phone-auth.js';
import { ApprovalError, approveRequest, getPending, rejectRequest } from '../services/approval.js';

export const approvals = new Hono();

// All routes require phone authentication
approvals.use('*', phoneAuthMiddleware);

/**
 * GET /api/approvals/pending — List pending approvals for the phone's tenant.
 */
approvals.get('/pending', async (c) => {
  const phone = c.get('phone');
  const pending = await getPending(phone.tenantId);

  return c.json({
    approvals: pending.map((a) => ({
      id: a.id,
      secret_id: a.secretId,
      reason: a.reason,
      challenge: Buffer.from(a.challenge).toString('base64url'),
      created_at: a.createdAt.toISOString(),
      expires_at: a.expiresAt.toISOString(),
    })),
  });
});

/**
 * POST /api/approvals/:id/approve — Approve a pending request with Ed25519 signature.
 */
approvals.post('/:id/approve', async (c) => {
  const phone = c.get('phone');
  const { id } = c.req.param();
  const body = await c.req.json<{ signature: string }>();

  if (!body.signature) {
    return c.json({ error: 'missing required field: signature' }, 400);
  }

  let signature: Uint8Array;
  try {
    signature = fromBase64Url(body.signature);
  } catch {
    return c.json({ error: 'invalid signature encoding' }, 400);
  }

  const phonePub = new Uint8Array(phone.ed25519Public);

  try {
    const result = await approveRequest(id, signature, phonePub);
    return c.json({
      id: result.id,
      status: result.status,
      responded_at: result.respondedAt?.toISOString(),
    });
  } catch (err) {
    if (err instanceof ApprovalError) {
      if (err.code === 'approval_not_found') return c.json({ error: err.message }, 404);
      if (err.code === 'already_resolved') return c.json({ error: err.message }, 409);
      if (err.code === 'expired') return c.json({ error: err.message }, 410);
      if (err.code === 'invalid_signature') return c.json({ error: err.message }, 400);
    }
    throw err;
  }
});

/**
 * POST /api/approvals/:id/reject — Reject a pending request.
 */
approvals.post('/:id/reject', async (c) => {
  const { id } = c.req.param();

  try {
    const result = await rejectRequest(id);
    return c.json({
      id: result.id,
      status: result.status,
      responded_at: result.respondedAt?.toISOString(),
    });
  } catch (err) {
    if (err instanceof ApprovalError) {
      if (err.code === 'approval_not_found') return c.json({ error: err.message }, 404);
      if (err.code === 'already_resolved') return c.json({ error: err.message }, 409);
    }
    throw err;
  }
});
