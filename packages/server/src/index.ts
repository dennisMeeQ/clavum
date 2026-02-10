import { serve } from '@hono/node-server';
import { app } from './app.js';

const port = parseInt(process.env.PORT ?? '3100', 10);

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`🔑 Clavum server running on http://localhost:${info.port}`);
});
