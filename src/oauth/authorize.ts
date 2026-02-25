import { Hono } from 'hono';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { sql } from '../db/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

export const authorizeGetRoute = new Hono();

// GET /oauth/authorize — show the subdomain entry form
authorizeGetRoute.get('/oauth/authorize', async (c) => {
  const { client_id, redirect_uri, response_type, code_challenge, code_challenge_method, state } =
    c.req.query();

  // Validate required params
  if (!client_id || !redirect_uri || response_type !== 'code' || !code_challenge || !state) {
    return c.text('Missing required OAuth parameters', 400);
  }

  if (code_challenge_method && code_challenge_method !== 'S256') {
    return c.text('Only S256 code_challenge_method is supported', 400);
  }

  // Validate client exists
  const clients = await sql`
    SELECT id, redirect_uris FROM our_clients WHERE id = ${client_id}
  `;
  if (clients.length === 0) {
    return c.text('Unknown client_id', 400);
  }

  const client = clients[0];
  const allowedRedirects: string[] = client.redirect_uris;
  if (!allowedRedirects.includes(redirect_uri)) {
    return c.text('redirect_uri not registered for this client', 400);
  }

  // Render the consent/subdomain form
  const html = readFileSync(join(__dirname, '../views/consent.html'), 'utf-8')
    .replace('{{CLIENT_ID}}', encodeURIComponent(client_id))
    .replace('{{REDIRECT_URI}}', encodeURIComponent(redirect_uri))
    .replace('{{CODE_CHALLENGE}}', encodeURIComponent(code_challenge))
    .replace('{{CODE_CHALLENGE_METHOD}}', encodeURIComponent(code_challenge_method ?? 'S256'))
    .replace('{{STATE}}', encodeURIComponent(state));

  return c.html(html);
});
