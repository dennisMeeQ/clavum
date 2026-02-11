/**
 * Secret metadata API routes.
 *
 * Manages secret registration, listing, and deletion.
 * All routes require authenticated agent (auth middleware).
 */

import { aes256gcm, flows, fromBase64Url, toBase64Url, wipe, x25519 } from '@clavum/crypto';
import { Hono } from 'hono';
import { prisma } from '../db.js';
import { authMiddleware } from '../middleware/auth.js';
import { createEntry } from '../services/audit.js';

export const secrets = new Hono();

// All routes require authentication
secrets.use('*', authMiddleware);

/**
 * POST /api/secrets/register — Register secret metadata.
 */
secrets.post('/register', async (c) => {
  const agent = c.get('agent');
  const body = await c.req.json<{ secret_id: string; name: string; tier: string }>();

  if (!body.secret_id || !body.name || !body.tier) {
    return c.json({ error: 'missing required fields: secret_id, name, tier' }, 400);
  }

  if (!['green', 'yellow', 'red'].includes(body.tier)) {
    return c.json({ error: 'invalid tier: must be green, yellow, or red' }, 400);
  }

  // Check for duplicate name
  const existing = await prisma.secretMetadata.findUnique({
    where: {
      agentId_name: {
        agentId: agent.id,
        name: body.name,
      },
    },
  });

  if (existing) {
    return c.json({ error: 'secret with this name already exists' }, 409);
  }

  const secret = await prisma.secretMetadata.create({
    data: {
      id: body.secret_id,
      tenantId: agent.tenantId,
      agentId: agent.id,
      name: body.name,
      tier: body.tier as 'green' | 'yellow' | 'red',
    },
  });

  return c.json({ id: secret.id, name: secret.name, tier: secret.tier }, 201);
});

/**
 * GET /api/secrets — List secrets for authenticated agent.
 */
secrets.get('/', async (c) => {
  const agent = c.get('agent');

  const secretsList = await prisma.secretMetadata.findMany({
    where: { agentId: agent.id },
    select: {
      id: true,
      name: true,
      tier: true,
      createdAt: true,
    },
    orderBy: { name: 'asc' },
  });

  return c.json({ secrets: secretsList });
});

/**
 * POST /api/secrets/:id/retrieve — Green-tier secret retrieval.
 *
 * Server derives KEK from ephemeral ECDH, encrypts it with K_session for transport.
 */
secrets.post('/:id/retrieve', async (c) => {
  const startMs = Date.now();
  const agent = c.get('agent');
  const secretId = c.req.param('id');

  const body = await c.req.json<{ eph_x25519_pub: string; kek_salt: string; reason: string }>();

  if (!body.eph_x25519_pub || !body.kek_salt || !body.reason) {
    return c.json({ error: 'missing required fields: eph_x25519_pub, kek_salt, reason' }, 400);
  }

  // Look up secret metadata
  const secret = await prisma.secretMetadata.findUnique({
    where: { id: secretId },
  });

  if (!secret) {
    return c.json({ error: 'secret not found' }, 404);
  }

  if (secret.agentId !== agent.id) {
    return c.json({ error: 'forbidden' }, 403);
  }

  if (secret.tier !== 'green') {
    return c.json({ error: 'this endpoint only supports green-tier secrets' }, 400);
  }

  // Load server private key for the agent's tenant
  const tenant = await prisma.tenant.findUnique({
    where: { id: agent.tenantId },
  });

  if (!tenant) {
    return c.json({ error: 'internal error' }, 500);
  }

  const serverPriv = new Uint8Array(tenant.x25519Private);
  const agentPub = new Uint8Array(agent.x25519Public);
  const ephPub = fromBase64Url(body.eph_x25519_pub);
  const kekSalt = fromBase64Url(body.kek_salt);

  // Derive KEK: X25519(server_priv, eph_pub) → HKDF → KEK
  const kek = flows.deriveGreenKek(serverPriv, ephPub, kekSalt, secretId);

  // Derive K_session: X25519(server_priv, agent_pub) — stable transport key
  const kSession = x25519.sharedSecret(serverPriv, agentPub);

  // Encrypt KEK for transport using K_session
  const { ciphertext: encKek, iv: encKekIv, tag: encKekTag } = aes256gcm.encrypt(kSession, kek);

  // Wipe sensitive material
  wipe(kek);
  wipe(kSession);

  // Audit log
  const latencyMs = Date.now() - startMs;
  await createEntry({
    agentId: agent.id,
    secretId,
    reason: body.reason,
    tier: 'green',
    result: 'auto_granted',
    latencyMs,
  });

  return c.json({
    enc_kek: toBase64Url(encKek),
    enc_kek_iv: toBase64Url(encKekIv),
    enc_kek_tag: toBase64Url(encKekTag),
  });
});

/**
 * DELETE /api/secrets/:id — Deregister a secret. Only owning agent can delete.
 */
secrets.delete('/:id', async (c) => {
  const agent = c.get('agent');
  const secretId = c.req.param('id');

  const secret = await prisma.secretMetadata.findUnique({
    where: { id: secretId },
  });

  if (!secret) {
    return c.json({ error: 'secret not found' }, 404);
  }

  if (secret.agentId !== agent.id) {
    return c.json({ error: 'forbidden' }, 403);
  }

  await prisma.secretMetadata.delete({
    where: { id: secretId },
  });

  return c.body(null, 204);
});
