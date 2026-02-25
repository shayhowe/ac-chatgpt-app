import { serve } from '@hono/node-server';
import { app } from './app.js';
import { initDb } from './db/index.js';

const PORT = parseInt(process.env.PORT ?? '3000', 10);

async function main() {
  await initDb();

  serve({ fetch: app.fetch, port: PORT }, (info) => {
    console.log(`AC MCP Gateway listening on port ${info.port}`);
  });
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
