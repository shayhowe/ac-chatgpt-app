import { Hono } from 'hono';
import { sql } from '../db/index.js';
import { generateCodeVerifier, deriveCodeChallenge, generateState } from '../crypto.js';

export const authorizePostRoute = new Hono();

const AC_TOKEN_URL = 'https://oauth2.app-us1.com/oauth2/auth';

function getBaseUrl(): string {
  return process.env.BASE_URL ?? 'http://localhost:3000';
}

// POST /oauth/authorize — handle subdomain submission, AC DCR, redirect to AC
authorizePostRoute.post('/oauth/authorize', async (c) => {
  let body: Record<string, string>;
  const contentType = c.req.header('content-type') ?? '';

  if (contentType.includes('application/x-www-form-urlencoded')) {
    const formData = await c.req.formData();
    body = Object.fromEntries(
      [...formData.entries()].map(([k, v]) => [k, String(v)]),
    );
  } else {
    return c.text('Expected application/x-www-form-urlencoded', 400);
  }

  const {
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    state: chatgptState,
    subdomain,
  } = body;

  // Validate required fields
  if (!client_id || !redirect_uri || !code_challenge || !chatgptState || !subdomain) {
    return c.text('Missing required fields', 400);
  }

  // Sanitize subdomain: only allow alphanumeric and hyphens
  if (!/^[a-z0-9-]+$/i.test(subdomain)) {
    return c.text('Invalid subdomain format', 400);
  }

  // Validate client exists and redirect_uri is allowed
  const clients = await sql`
    SELECT id, redirect_uris FROM our_clients WHERE id = ${client_id}
  `;
  if (clients.length === 0) {
    return c.text('Unknown client_id', 400);
  }
  const allowedRedirects: string[] = clients[0].redirect_uris;
  if (!allowedRedirects.includes(redirect_uri)) {
    return c.text('redirect_uri not registered for this client', 400);
  }

  // Step 1: Register with AC's OAuth server (Dynamic Client Registration)
  const acDcrUrl = `https://${subdomain}.activehosted.com/api/public/oauth2/register.php`;
  const acCallbackUri = `${getBaseUrl()}/ac/callback`;

  let acClientId: string;
  try {
    const dcrResp = await fetch(acDcrUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: [acCallbackUri],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        client_name: 'ChatGPT AC MCP Gateway',
      }),
    });

    if (!dcrResp.ok) {
      const text = await dcrResp.text();
      console.error('AC DCR failed:', dcrResp.status, text);
      return c.html(errorPage('Could not register with ActiveCampaign. Is your subdomain correct?'), 400);
    }

    const dcrData = (await dcrResp.json()) as { client_id?: string };
    if (!dcrData.client_id) {
      return c.html(errorPage('ActiveCampaign registration did not return a client_id'), 400);
    }
    acClientId = dcrData.client_id;
  } catch (err) {
    console.error('AC DCR network error:', err);
    return c.html(errorPage('Network error contacting ActiveCampaign'), 502);
  }

  // Step 2: Generate our PKCE pair for the AC leg
  const acCodeVerifier = generateCodeVerifier();
  const acCodeChallenge = deriveCodeChallenge(acCodeVerifier);

  // Step 3: Generate a state value that ties this AC callback back to our session
  const ourState = generateState();

  // Step 4: Store the pending session
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
  await sql`
    INSERT INTO pending_sessions (
      state, our_client_id, chatgpt_redirect_uri, chatgpt_code_challenge, chatgpt_state,
      ac_subdomain, ac_client_id, ac_code_verifier, expires_at
    ) VALUES (
      ${ourState}, ${client_id}, ${redirect_uri}, ${code_challenge}, ${chatgptState},
      ${subdomain}, ${acClientId}, ${acCodeVerifier}, ${expiresAt}
    )
  `;

  // Step 5: Redirect user to AC's authorization endpoint
  const acAuthUrl = new URL(AC_TOKEN_URL);
  acAuthUrl.searchParams.set('client_id', acClientId);
  acAuthUrl.searchParams.set('redirect_uri', acCallbackUri);
  acAuthUrl.searchParams.set('scope', 'org:read project:write team:write event:write');
  acAuthUrl.searchParams.set('response_type', 'code');
  acAuthUrl.searchParams.set('code_challenge', acCodeChallenge);
  acAuthUrl.searchParams.set('code_challenge_method', 'S256');
  acAuthUrl.searchParams.set('state', ourState);

  return c.redirect(acAuthUrl.toString());
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
  <p><a href="javascript:history.back()">← Go back</a></p>
</body>
</html>`;
}
