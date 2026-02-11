/**
 * Audit log query API routes.
 *
 * Returns audit entries scoped to the authenticated agent's secrets.
 */

import { Hono } from 'hono';
import { authMiddleware } from '../middleware/auth.js';
import { queryEntries } from '../services/audit.js';

export const audit = new Hono();

audit.use('*', authMiddleware);

/**
 * GET /api/audit — Query audit log entries for authenticated agent.
 * Query params: secret_id, from, to, limit (default 50)
 */
audit.get('/', async (c) => {
  const agent = c.get('agent');

  const secretId = c.req.query('secret_id');
  const fromStr = c.req.query('from');
  const toStr = c.req.query('to');
  const limitStr = c.req.query('limit');

  const entries = await queryEntries({
    agentId: agent.id,
    secretId: secretId || undefined,
    from: fromStr ? new Date(fromStr) : undefined,
    to: toStr ? new Date(toStr) : undefined,
    limit: limitStr ? Number.parseInt(limitStr, 10) : 50,
  });

  return c.json({ entries });
});
