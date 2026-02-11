/**
 * Secret metadata API routes.
 *
 * Manages secret registration, listing, and deletion.
 * All routes require authenticated agent (auth middleware).
 */

import { Hono } from 'hono';
import { prisma } from '../db.js';
import { authMiddleware } from '../middleware/auth.js';

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
