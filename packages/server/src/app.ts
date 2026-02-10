import { Hono } from 'hono';

export const app = new Hono();

app.get('/health', (c) => c.json({ status: 'ok', service: 'clavum' }));

// TODO: Routes
// POST /api/pair/agent — agent pairing
// POST /api/pair/phone — phone pairing
// POST /api/secrets/:id/retrieve — secret retrieval (green/yellow/red flows)
// POST /api/secrets/:id/register — register secret metadata
// POST /api/approval/:id/respond — phone approval response
// GET  /api/audit — audit log
