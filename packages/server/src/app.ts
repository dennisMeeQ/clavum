import { Hono } from 'hono';
import { pair } from './routes/pair.js';
import { tenants } from './routes/tenants.js';

export const app = new Hono();

app.get('/health', (c) => c.json({ status: 'ok', service: 'clavum' }));

// API routes
app.route('/api/tenants', tenants);
app.route('/api/pair', pair);
