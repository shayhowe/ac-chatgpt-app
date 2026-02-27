import { Hono } from 'hono';
import { metadataRoutes } from './oauth/metadata.js';
import { registerRoute } from './oauth/register.js';
import { authorizeGetRoute } from './oauth/authorize.js';
import { authorizePostRoute } from './oauth/authorize-submit.js';
import { acCallbackRoute } from './oauth/ac-callback.js';
import { tokenRoute } from './oauth/token.js';
import { mcpProxyRoute } from './mcp/proxy.js';

export const app = new Hono();

app.onError((err, c) => {
  console.error(`${c.req.method} ${c.req.path}`, err);
  return c.json({ error: 'internal_error', error_description: err.message }, 500);
});

// Request/response logging
app.use('*', async (c, next) => {
  const start = Date.now();
  await next();
  const ms = Date.now() - start;
  console.log(`${c.req.method} ${c.req.path} → ${c.res.status} (${ms}ms)`);
});

// OAuth 2.1 metadata discovery
app.route('/', metadataRoutes);

// Our OAuth 2.1 server endpoints
app.route('/', registerRoute);
app.route('/', authorizeGetRoute);
app.route('/', authorizePostRoute);
app.route('/', acCallbackRoute);
app.route('/', tokenRoute);

// MCP proxy
app.route('/', mcpProxyRoute);

// Health check
app.get('/health', (c) => c.json({ status: 'ok' }));
