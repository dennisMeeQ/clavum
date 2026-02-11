/**
 * Phone authentication middleware.
 *
 * Verifies Ed25519 request signatures from paired phones.
 * Same pattern as agent auth but uses X-Phone-Id header.
 */

import { createHash } from 'node:crypto';
import { signatures } from '@clavum/crypto';
import type { Phone } from '@prisma/client';
import type { Context, Next } from 'hono';
import { prisma } from '../db.js';
import { isReplay, storeNonce } from '../services/nonce.js';

declare module 'hono' {
  interface ContextVariableMap {
    phone: Phone;
  }
}

/**
 * Auth middleware for phone endpoints.
 * Requires X-Phone-Id, X-Timestamp, X-Signature headers.
 */
export async function phoneAuthMiddleware(c: Context, next: Next): Promise<Response | undefined> {
  const phoneId = c.req.header('x-phone-id');
  const timestamp = c.req.header('x-timestamp');
  const signatureB64 = c.req.header('x-signature');

  if (!phoneId || !timestamp || !signatureB64) {
    return c.json({ error: 'missing authentication headers' }, 401);
  }

  // Look up phone (use generic 401 to avoid enumeration)
  const phone = await prisma.phone.findUnique({
    where: { id: phoneId },
  });

  if (!phone) {
    return c.json({ error: 'authentication failed' }, 401);
  }

  // Read body as text, encode to bytes
  const bodyText = await c.req.text();
  const bodyBytes = new TextEncoder().encode(bodyText);
  const sig = new Uint8Array(Buffer.from(signatureB64, 'base64url'));
  const pubKey = new Uint8Array(phone.ed25519Public);

  // Verify signature (includes 60s timestamp check)
  const method = c.req.method;
  const path = new URL(c.req.url).pathname;

  const valid = signatures.verifyRequest(pubKey, timestamp, method, path, bodyBytes, sig);

  if (!valid) {
    return c.json({ error: 'authentication failed' }, 401);
  }

  // Nonce dedup: hash signature to check for replay
  const sigHash = createHash('sha256').update(sig).digest('hex');

  if (await isReplay(sigHash)) {
    return c.json({ error: 'replayed request' }, 409);
  }

  // Store nonce with 120s expiry (2x the window for safety)
  await storeNonce(sigHash, new Date(Date.now() + 120_000));

  // Set phone on context
  c.set('phone', phone);
  await next();
}
