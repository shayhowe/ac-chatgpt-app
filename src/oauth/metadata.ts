import { Hono } from 'hono';

export const metadataRoutes = new Hono();

function getBaseUrl(): string {
  return process.env.BASE_URL ?? 'http://localhost:3000';
}

// ── Protected Resource Metadata ───────────────────────────────────────────────
// RFC 9728 — tells clients which authorization server governs this resource
metadataRoutes.get('/.well-known/oauth-protected-resource', (c) => {
  const base = getBaseUrl();
  return c.json({
    resource: `${base}/mcp`,
    authorization_servers: [base],
    scopes_supported: ['mcp'],
    bearer_methods_supported: ['header'],
  });
});

// ── Authorization Server Metadata ────────────────────────────────────────────
// RFC 8414 — served at both standard path and /mcp alias (ChatGPT requirement)
function asMetadata(base: string) {
  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: ['mcp'],
  };
}

metadataRoutes.get('/.well-known/oauth-authorization-server', (c) => {
  return c.json(asMetadata(getBaseUrl()));
});

// ChatGPT also fetches this path when the resource is at /mcp
metadataRoutes.get('/.well-known/oauth-authorization-server/mcp', (c) => {
  return c.json(asMetadata(getBaseUrl()));
});
