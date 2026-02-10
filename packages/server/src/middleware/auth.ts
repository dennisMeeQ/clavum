/**
 * Request authentication middleware.
 *
 * Verifies Ed25519 request signatures from paired agents.
 * Checks: signature validity, timestamp window (60s), nonce replay.
 */

import { createHash } from 'node:crypto';
import { signatures } from '@clavum/crypto';
import type { Agent } from '@prisma/client';
import type { Context, Next } from 'hono';
import { prisma } from '../db.js';

declare module 'hono' {
  interface ContextVariableMap {
    agent: Agent;
  }
}

/**
 * Auth middleware for Hono.
 * Requires X-Agent-Id, X-Timestamp, X-Signature headers.
 */
export async function authMiddleware(c: Context, next: Next): Promise<Response | void> {
  const agentId = c.req.header('x-agent-id');
  const timestamp = c.req.header('x-timestamp');
  const signatureB64 = c.req.header('x-signature');

  if (!agentId || !timestamp || !signatureB64) {
    return c.json({ error: 'missing authentication headers' }, 401);
  }

  // Look up agent (use generic 401 to avoid enumeration)
  const agent = await prisma.agent.findUnique({
    where: { id: agentId },
  });

  if (!agent) {
    return c.json({ error: 'authentication failed' }, 401);
  }

  // Read body as text, encode to bytes
  const bodyText = await c.req.text();
  const bodyBytes = new TextEncoder().encode(bodyText);
  const sig = new Uint8Array(Buffer.from(signatureB64, 'base64url'));
  const pubKey = new Uint8Array(agent.ed25519Public);

  // Verify signature (includes 60s timestamp check)
  const method = c.req.method;
  const path = new URL(c.req.url).pathname;

  const valid = signatures.verifyRequest(pubKey, timestamp, method, path, bodyBytes, sig);

  if (!valid) {
    return c.json({ error: 'authentication failed' }, 401);
  }

  // Nonce dedup: hash signature to check for replay
  const sigHash = createHash('sha256').update(sig).digest('hex');
  const existing = await prisma.usedNonce.findUnique({
    where: { nonce: sigHash },
  });

  if (existing) {
    return c.json({ error: 'replayed request' }, 409);
  }

  // Store nonce with 120s expiry (2x the window for safety)
  await prisma.usedNonce.create({
    data: {
      nonce: sigHash,
      expiresAt: new Date(Date.now() + 120_000),
    },
  });

  // Set agent on context
  c.set('agent', agent);
  await next();
}
