import { Hono } from 'hono';
import { sql } from '../db/index.js';
import { encrypt, generateToken } from '../crypto.js';
import { randomBytes } from 'crypto';

export const acCallbackRoute = new Hono();

const AC_TOKEN_ENDPOINT = 'https://oauth2.app-us1.com/oauth2/token';

function getBaseUrl(): string {
  return process.env.BASE_URL ?? 'http://localhost:3000';
}

// GET /ac/callback — AC redirects here after user authorizes
acCallbackRoute.get('/ac/callback', async (c) => {
  const { code, state, error, error_description } = c.req.query();

  if (error) {
    console.error('AC OAuth error:', error, error_description);
    return c.html(errorPage(`ActiveCampaign denied access: ${error_description ?? error}`), 400);
  }

  if (!code || !state) {
    return c.html(errorPage('Missing code or state from ActiveCampaign'), 400);
  }

  // Look up our pending session by state
  const sessions = await sql`
    SELECT * FROM pending_sessions
    WHERE state = ${state} AND expires_at > NOW()
  `;

  if (sessions.length === 0) {
    return c.html(errorPage('OAuth session expired or not found. Please start over.'), 400);
  }

  const session = sessions[0];

  // Clean up pending session immediately (one-time use)
  await sql`DELETE FROM pending_sessions WHERE state = ${state}`;

  // Exchange AC code for AC tokens
  const acCallbackUri = `${getBaseUrl()}/ac/callback`;

  let acAccessToken: string;
  let acRefreshToken: string;
  let acExpiresIn: number;

  try {
    const tokenResp = await fetch(AC_TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: session.ac_client_id,
        redirect_uri: acCallbackUri,
        code_verifier: session.ac_code_verifier,
      }),
    });

    if (!tokenResp.ok) {
      const text = await tokenResp.text();
      console.error('AC token exchange failed:', tokenResp.status, text);
      return c.html(errorPage('Failed to get access token from ActiveCampaign'), 502);
    }

    const tokenData = (await tokenResp.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
    };

    if (!tokenData.access_token) {
      console.error('AC token response missing access_token:', JSON.stringify(tokenData));
      return c.html(errorPage('ActiveCampaign did not return a valid access token'), 502);
    }

    acAccessToken = tokenData.access_token;
    acRefreshToken = tokenData.refresh_token ?? '';
    acExpiresIn = tokenData.expires_in ?? 3600;
  } catch (err) {
    console.error('AC token exchange network error:', err);
    return c.html(errorPage('Network error during token exchange'), 502);
  }

  // Encrypt tokens before storing
  const encryptedAccessToken = encrypt(acAccessToken);
  const encryptedRefreshToken = encrypt(acRefreshToken);
  const acTokenExpiresAt = new Date(Date.now() + acExpiresIn * 1000);

  // Create user session record with a temporary unique placeholder for the token hash.
  // token.ts will overwrite this with the real SHA-256 hash after code exchange.
  const tempTokenHash = randomBytes(32).toString('hex');

  const [userSession] = await sql`
    INSERT INTO user_sessions (
      our_token_hash, ac_subdomain, ac_client_id,
      ac_access_token_enc, ac_refresh_token_enc, ac_token_expires_at
    )
    VALUES (
      ${tempTokenHash}, ${session.ac_subdomain}, ${session.ac_client_id},
      ${encryptedAccessToken}, ${encryptedRefreshToken}, ${acTokenExpiresAt}
    )
    RETURNING id
  `;

  const userId: string = userSession.id;

  // Issue our own auth code for ChatGPT
  const ourCode = generateToken();
  const codeExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  await sql`
    INSERT INTO our_codes (
      code, user_id, our_client_id,
      chatgpt_redirect_uri, chatgpt_code_challenge, expires_at
    )
    VALUES (
      ${ourCode}, ${userId}, ${session.our_client_id},
      ${session.chatgpt_redirect_uri}, ${session.chatgpt_code_challenge}, ${codeExpiresAt}
    )
  `;

  // Redirect ChatGPT back with our code + their original state
  const redirectUrl = new URL(session.chatgpt_redirect_uri);
  redirectUrl.searchParams.set('code', ourCode);
  redirectUrl.searchParams.set('state', session.chatgpt_state);

  return c.redirect(redirectUrl.toString());
});

function errorPage(message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error — AC MCP Gateway</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 24px; color: #333; }
    .error { background: #fef2f2; border: 1px solid #fca5a5; border-radius: 8px; padding: 16px; color: #991b1b; }
    a { color: #2563eb; }
  </style>
</head>
<body>
  <h2>Something went wrong</h2>
  <div class="error">${message}</div>
</body>
</html>`;
}
