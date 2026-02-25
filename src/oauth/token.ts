import { Hono } from 'hono';
import { sql } from '../db/index.js';
import { validatePkce, generateToken, hashToken } from '../crypto.js';

export const tokenRoute = new Hono();

// POST /oauth/token — exchange our code for our opaque token
tokenRoute.post('/oauth/token', async (c) => {
  let params: URLSearchParams;

  const contentType = c.req.header('content-type') ?? '';
  if (contentType.includes('application/x-www-form-urlencoded')) {
    const text = await c.req.text();
    params = new URLSearchParams(text);
  } else if (contentType.includes('application/json')) {
    const body = (await c.req.json()) as Record<string, string>;
    params = new URLSearchParams(body);
  } else {
    return c.json({ error: 'invalid_request', error_description: 'Unsupported content-type' }, 400);
  }

  const grantType = params.get('grant_type');
  if (grantType !== 'authorization_code') {
    return c.json(
      { error: 'unsupported_grant_type', error_description: 'Only authorization_code is supported' },
      400,
    );
  }

  const code = params.get('code');
  const codeVerifier = params.get('code_verifier');
  const clientId = params.get('client_id');

  if (!code || !codeVerifier || !clientId) {
    return c.json(
      { error: 'invalid_request', error_description: 'Missing code, code_verifier, or client_id' },
      400,
    );
  }

  // Look up the code
  const codes = await sql`
    SELECT * FROM our_codes
    WHERE code = ${code} AND expires_at > NOW()
  `;

  if (codes.length === 0) {
    return c.json(
      { error: 'invalid_grant', error_description: 'Code not found or expired' },
      400,
    );
  }

  const ourCode = codes[0];

  // Validate client matches
  if (ourCode.our_client_id !== clientId) {
    return c.json(
      { error: 'invalid_client', error_description: 'client_id does not match' },
      400,
    );
  }

  // Validate PKCE
  if (!validatePkce(codeVerifier, ourCode.chatgpt_code_challenge)) {
    return c.json(
      { error: 'invalid_grant', error_description: 'PKCE verification failed' },
      400,
    );
  }

  // Consume the code (one-time use)
  await sql`DELETE FROM our_codes WHERE code = ${code}`;

  // Issue our opaque access token
  const rawToken = generateToken();
  const tokenHash = hashToken(rawToken);

  // Update user_sessions to record the actual token hash
  // (session was created with 'pending' placeholder during ac-callback)
  await sql`
    UPDATE user_sessions
    SET our_token_hash = ${tokenHash}, last_used_at = NOW()
    WHERE id = ${ourCode.user_id}
  `;

  return c.json({
    access_token: rawToken,
    token_type: 'bearer',
    // No expiry for our tokens — AC tokens refresh transparently
    // ChatGPT will re-auth if it gets a 401 from us
  });
});
