import { Hono } from 'hono';
import { z } from 'zod';
import { sql } from '../db/index.js';

export const registerRoute = new Hono();

const ALLOWED_REDIRECT_PREFIXES = [
  'https://chatgpt.com/',
  'https://platform.openai.com/',
  // Allow localhost for development/testing
  'http://localhost',
  'https://localhost',
];

function isAllowedRedirectUri(uri: string): boolean {
  return ALLOWED_REDIRECT_PREFIXES.some((prefix) => uri.startsWith(prefix));
}

const DCRRequestSchema = z.object({
  redirect_uris: z.array(z.string().url()).min(1),
  client_name: z.string().optional(),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
  token_endpoint_auth_method: z.string().optional(),
});

// POST /oauth/register — Dynamic Client Registration (our server)
registerRoute.post('/oauth/register', async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'invalid_request', error_description: 'Request body must be JSON' }, 400);
  }

  const parsed = DCRRequestSchema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      { error: 'invalid_client_metadata', error_description: parsed.error.message },
      400,
    );
  }

  const { redirect_uris, client_name } = parsed.data;

  // Validate all redirect URIs
  for (const uri of redirect_uris) {
    if (!isAllowedRedirectUri(uri)) {
      return c.json(
        {
          error: 'invalid_redirect_uri',
          error_description: `Redirect URI not allowed: ${uri}`,
        },
        400,
      );
    }
  }

  const [client] = await sql`
    INSERT INTO our_clients (redirect_uris, client_name)
    VALUES (${JSON.stringify(redirect_uris)}, ${client_name ?? null})
    RETURNING id, redirect_uris, client_name, created_at
  `;

  return c.json(
    {
      client_id: client.id,
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    },
    201,
  );
});
