import { Hono } from 'hono';
import { tenants } from './routes/tenants.js';

export const app = new Hono();

app.get('/health', (c) => c.json({ status: 'ok', service: 'clavum' }));

// API routes
app.route('/api/tenants', tenants);
