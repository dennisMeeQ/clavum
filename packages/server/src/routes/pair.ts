import { randomBytes } from 'node:crypto';
import { fingerprintToEmoji, kdf, x25519 } from '@clavum/crypto';
import { Hono } from 'hono';
import { prisma } from '../db.js';

export const pair = new Hono();

const INVITE_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes

/**
 * POST /api/pair/invite — Create a pairing invitation.
 */
pair.post('/invite', async (c) => {
  const body = await c.req.json<{ tenantId?: string; type?: string }>();

  if (!body.tenantId || !body.type || !['agent', 'phone'].includes(body.type)) {
    return c.json({ error: 'tenantId and type (agent|phone) required' }, 400);
  }

  const tenant = await prisma.tenant.findUnique({
    where: { id: body.tenantId },
    select: { id: true, x25519Public: true },
  });

  if (!tenant) {
    return c.json({ error: 'tenant not found' }, 404);
  }

  const token = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + INVITE_EXPIRY_MS);

  const invitation = await prisma.pairingInvitation.create({
    data: {
      tenantId: tenant.id,
      token,
      type: body.type,
      expiresAt,
    },
  });

  // QR payload
  const serverUrl = c.req.header('x-server-url') || `${new URL(c.req.url).origin}`;
  const qrPayload = {
    pub: Buffer.from(tenant.x25519Public).toString('base64url'),
    token,
    url: serverUrl,
  };

  return c.json(
    {
      id: invitation.id,
      token,
      expiresAt: invitation.expiresAt,
      qr: qrPayload,
    },
    201,
  );
});

/**
 * POST /api/pair/agent — Register an agent via pairing token.
 */
pair.post('/agent', async (c) => {
  const body = await c.req.json<{
    token?: string;
    x25519_pub?: string;
    ed25519_pub?: string;
    name?: string;
  }>();

  if (!body.token || !body.x25519_pub || !body.ed25519_pub || !body.name) {
    return c.json({ error: 'token, x25519_pub, ed25519_pub, and name are required' }, 400);
  }

  const invitation = await prisma.pairingInvitation.findUnique({
    where: { token: body.token },
    include: { tenant: true },
  });

  if (!invitation) {
    return c.json({ error: 'invalid token' }, 404);
  }

  if (invitation.used) {
    return c.json({ error: 'token already used' }, 400);
  }

  if (invitation.expiresAt < new Date()) {
    return c.json({ error: 'token expired' }, 400);
  }

  const agentX25519Pub = new Uint8Array(Buffer.from(body.x25519_pub, 'base64url'));
  const agentEd25519Pub = new Uint8Array(Buffer.from(body.ed25519_pub, 'base64url'));

  // Register agent
  const agent = await prisma.agent.create({
    data: {
      tenantId: invitation.tenantId,
      name: body.name,
      x25519Public: Buffer.from(agentX25519Pub),
      ed25519Public: Buffer.from(agentEd25519Pub),
    },
  });

  // Invalidate token
  await prisma.pairingInvitation.update({
    where: { id: invitation.id },
    data: { used: true },
  });

  // Derive fingerprint
  const serverPriv = new Uint8Array(invitation.tenant.x25519Private);
  const sharedSecret = x25519.sharedSecret(serverPriv, agentX25519Pub);
  const fingerprintBytes = kdf.deriveFingerprint(sharedSecret);
  const fingerprint = fingerprintToEmoji(fingerprintBytes);

  return c.json({
    agentId: agent.id,
    serverX25519Pub: Buffer.from(invitation.tenant.x25519Public).toString('base64url'),
    fingerprint,
  });
});

/**
 * POST /api/pair/phone — Register a phone via pairing token.
 */
pair.post('/phone', async (c) => {
  const body = await c.req.json<{
    token?: string;
    x25519_pub?: string;
    ed25519_pub?: string;
    name?: string;
  }>();

  if (!body.token || !body.x25519_pub || !body.ed25519_pub) {
    return c.json({ error: 'token, x25519_pub, and ed25519_pub are required' }, 400);
  }

  const invitation = await prisma.pairingInvitation.findUnique({
    where: { token: body.token },
    include: { tenant: true },
  });

  if (!invitation) {
    return c.json({ error: 'invalid token' }, 404);
  }

  if (invitation.used) {
    return c.json({ error: 'token already used' }, 400);
  }

  if (invitation.expiresAt < new Date()) {
    return c.json({ error: 'token expired' }, 400);
  }

  const phoneX25519Pub = new Uint8Array(Buffer.from(body.x25519_pub, 'base64url'));
  const phoneEd25519Pub = new Uint8Array(Buffer.from(body.ed25519_pub, 'base64url'));

  // Register phone
  const phone = await prisma.phone.create({
    data: {
      tenantId: invitation.tenantId,
      name: body.name || 'Phone',
      x25519Public: Buffer.from(phoneX25519Pub),
      ed25519Public: Buffer.from(phoneEd25519Pub),
    },
  });

  // Invalidate token
  await prisma.pairingInvitation.update({
    where: { id: invitation.id },
    data: { used: true },
  });

  // Derive fingerprint
  const serverPriv = new Uint8Array(invitation.tenant.x25519Private);
  const sharedSecret = x25519.sharedSecret(serverPriv, phoneX25519Pub);
  const fingerprintBytes = kdf.deriveFingerprint(sharedSecret);
  const fingerprint = fingerprintToEmoji(fingerprintBytes);

  return c.json({
    phoneId: phone.id,
    serverX25519Pub: Buffer.from(invitation.tenant.x25519Public).toString('base64url'),
    fingerprint,
  });
});
