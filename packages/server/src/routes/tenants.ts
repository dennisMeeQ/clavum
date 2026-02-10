import { x25519 } from '@clavum/crypto';
import { Hono } from 'hono';
import { prisma } from '../db.js';

export const tenants = new Hono();

/**
 * POST /api/tenants — Create a new tenant with server keypair.
 */
tenants.post('/', async (c) => {
  const body = await c.req.json<{ name?: string }>();

  if (!body.name || typeof body.name !== 'string') {
    return c.json({ error: 'name is required' }, 400);
  }

  const keypair = x25519.generateKeypair();

  const tenant = await prisma.tenant.create({
    data: {
      name: body.name,
      x25519Private: Buffer.from(keypair.privateKey),
      x25519Public: Buffer.from(keypair.publicKey),
    },
  });

  return c.json(
    {
      id: tenant.id,
      name: tenant.name,
      x25519Public: Buffer.from(tenant.x25519Public).toString('base64url'),
      createdAt: tenant.createdAt,
    },
    201,
  );
});

/**
 * GET /api/tenants/:id — Get tenant info (public key only).
 */
tenants.get('/:id', async (c) => {
  const id = c.req.param('id');

  const tenant = await prisma.tenant.findUnique({
    where: { id },
    select: { id: true, name: true, x25519Public: true, createdAt: true },
  });

  if (!tenant) {
    return c.json({ error: 'tenant not found' }, 404);
  }

  return c.json({
    id: tenant.id,
    name: tenant.name,
    x25519Public: Buffer.from(tenant.x25519Public).toString('base64url'),
    createdAt: tenant.createdAt,
  });
});
