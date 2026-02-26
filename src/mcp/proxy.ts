import { Hono } from 'hono';
import { sql, type UserSession } from '../db/index.js';
import { hashToken, decrypt, encrypt } from '../crypto.js';

export const mcpProxyRoute = new Hono();

const AC_TOKEN_ENDPOINT = 'https://oauth2.app-us1.com/oauth2/token';
const TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000; // refresh if within 5 minutes of expiry

function getBaseUrl(): string {
  return process.env.BASE_URL ?? 'http://localhost:3000';
}

// GET /mcp — return 401 with WWW-Authenticate to trigger OAuth discovery
mcpProxyRoute.get('/mcp', (c) => {
  const base = getBaseUrl();
  c.header(
    'WWW-Authenticate',
    `Bearer realm="${base}", resource_metadata="${base}/.well-known/oauth-protected-resource"`,
  );
  return c.json({ error: 'unauthorized', error_description: 'Authentication required' }, 401);
});

// POST /mcp — validate token, proxy request to AC
mcpProxyRoute.post('/mcp', async (c) => {
  const base = getBaseUrl();
  const authHeader = c.req.header('authorization') ?? '';

  if (!authHeader.startsWith('Bearer ')) {
    c.header(
      'WWW-Authenticate',
      `Bearer realm="${base}", resource_metadata="${base}/.well-known/oauth-protected-resource"`,
    );
    return c.json({ error: 'unauthorized', error_description: 'Bearer token required' }, 401);
  }

  const rawToken = authHeader.slice('Bearer '.length).trim();
  const tokenHash = hashToken(rawToken);

  // Look up user session
  const sessions = await sql<UserSession[]>`
    SELECT * FROM user_sessions WHERE our_token_hash = ${tokenHash}
  `;

  if (sessions.length === 0) {
    c.header(
      'WWW-Authenticate',
      `Bearer realm="${base}", error="invalid_token", resource_metadata="${base}/.well-known/oauth-protected-resource"`,
    );
    return c.json({ error: 'invalid_token', error_description: 'Token not found' }, 401);
  }

  let session = sessions[0];

  // Refresh AC token if near expiry
  const expiresAt = new Date(session.ac_token_expires_at).getTime();
  if (expiresAt - Date.now() < TOKEN_REFRESH_BUFFER_MS) {
    const refreshed = await refreshAcToken(session);
    if (!refreshed) {
      // Refresh failed — force re-auth
      c.header(
        'WWW-Authenticate',
        `Bearer realm="${base}", error="invalid_token", resource_metadata="${base}/.well-known/oauth-protected-resource"`,
      );
      return c.json(
        { error: 'invalid_token', error_description: 'AC token refresh failed, please re-authenticate' },
        401,
      );
    }
    session = refreshed;
  }

  // Update last_used_at (fire-and-forget, non-critical)
  sql`UPDATE user_sessions SET last_used_at = NOW() WHERE id = ${session.id}`.catch(() => {});

  // Decrypt AC access token
  let acAccessToken: string;
  try {
    acAccessToken = decrypt(session.ac_access_token_enc);
  } catch {
    return c.json({ error: 'internal_error', error_description: 'Token decryption failed' }, 500);
  }

  // Forward request body verbatim to AC MCP server
  const acMcpUrl = `https://${session.ac_subdomain}.activehosted.com/api/agents/mcp/http`;
  const requestBody = await c.req.arrayBuffer();

  let acResp: Response;
  try {
    acResp = await fetch(acMcpUrl, {
      method: 'POST',
      headers: {
        'Content-Type': c.req.header('content-type') ?? 'application/json',
        Authorization: `Bearer ${acAccessToken}`,
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': c.req.header('mcp-protocol-version') ?? '2025-03-26',
      },
      body: requestBody,
    });
  } catch (err) {
    console.error('AC MCP proxy network error:', err);
    return c.json({ error: 'bad_gateway', error_description: 'Could not reach ActiveCampaign MCP server' }, 502);
  }

  // If AC returns 401 → our token is revoked; force re-auth
  if (acResp.status === 401) {
    c.header(
      'WWW-Authenticate',
      `Bearer realm="${base}", error="invalid_token", resource_metadata="${base}/.well-known/oauth-protected-resource"`,
    );
    return c.json(
      { error: 'invalid_token', error_description: 'ActiveCampaign token revoked, please re-authenticate' },
      401,
    );
  }

  // Pass through AC response headers relevant to MCP
  const responseHeaders: Record<string, string> = {};
  const passThroughHeaders = ['content-type', 'mcp-protocol-version', 'cache-control'];
  for (const header of passThroughHeaders) {
    const val = acResp.headers.get(header);
    if (val) responseHeaders[header] = val;
  }

  // Stream or buffer the response body
  const acBody = await acResp.arrayBuffer();

  return new Response(acBody, {
    status: acResp.status,
    headers: responseHeaders,
  });
});

async function refreshAcToken(session: UserSession): Promise<UserSession | null> {
  let refreshToken: string;
  try {
    refreshToken = decrypt(session.ac_refresh_token_enc);
  } catch {
    return null;
  }

  // No refresh token stored — can't refresh
  if (!refreshToken) return null;

  try {
    const resp = await fetch(AC_TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: session.ac_client_id,
      }),
    });

    if (!resp.ok) {
      console.error('AC token refresh failed:', resp.status, await resp.text());
      return null;
    }

    const data = (await resp.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
    };

    if (!data.access_token) return null;

    const newExpiresAt = new Date(Date.now() + (data.expires_in ?? 3600) * 1000);
    const encAccessToken = encrypt(data.access_token);
    const encRefreshToken = data.refresh_token
      ? encrypt(data.refresh_token)
      : session.ac_refresh_token_enc;

    const updated = await sql<UserSession[]>`
      UPDATE user_sessions
      SET
        ac_access_token_enc = ${encAccessToken},
        ac_refresh_token_enc = ${encRefreshToken},
        ac_token_expires_at = ${newExpiresAt}
      WHERE id = ${session.id}
      RETURNING *
    `;

    return updated[0] ?? null;
  } catch (err) {
    console.error('AC token refresh error:', err);
    return null;
  }
}
