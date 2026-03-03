import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../db/index.js', () => {
  const mockSql = vi.fn().mockResolvedValue([]);
  (mockSql as unknown as Record<string, unknown>).json = vi.fn((v: unknown) => v);
  (mockSql as unknown as Record<string, unknown>).unsafe = vi.fn().mockResolvedValue([]);
  return { sql: mockSql };
});

import { authorizePostRoute } from '../oauth/authorize-submit.js';
import { sql } from '../db/index.js';

const mockSql = vi.mocked(sql);

const CLIENT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const REDIRECT_URI = 'https://chatgpt.com/aip/plugin-oauth/callback';

const validParams = {
  client_id: CLIENT_ID,
  redirect_uri: REDIRECT_URI,
  code_challenge: 'abc123challenge',
  code_challenge_method: 'S256',
  state: 'chatgpt-state',
  subdomain: 'mycompany',
};

function post(params: Record<string, string>) {
  return authorizePostRoute.request('/oauth/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
}

function mockAcDcrOk(clientId = 'ac-client-123') {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: () => Promise.resolve({ client_id: clientId }),
    text: () => Promise.resolve(''),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  // Default: client lookup returns a valid client; INSERT returns empty
  mockSql.mockResolvedValue([{ id: CLIENT_ID, redirect_uris: [REDIRECT_URI] }]);
  vi.stubGlobal('fetch', mockAcDcrOk());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('POST /oauth/authorize', () => {
  it('returns 400 for wrong content-type', async () => {
    const res = await authorizePostRoute.request('/oauth/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(validParams),
    });
    expect(res.status).toBe(400);
  });

  it('returns 400 when subdomain is missing', async () => {
    const { subdomain: _, ...rest } = validParams;
    const res = await post(rest as Record<string, string>);
    expect(res.status).toBe(400);
  });

  it('returns 400 when client_id is missing', async () => {
    const { client_id: _, ...rest } = validParams;
    const res = await post(rest as Record<string, string>);
    expect(res.status).toBe(400);
  });

  it('returns 400 when code_challenge is missing', async () => {
    const { code_challenge: _, ...rest } = validParams;
    const res = await post(rest as Record<string, string>);
    expect(res.status).toBe(400);
  });

  it('returns 400 when state is missing', async () => {
    const { state: _, ...rest } = validParams;
    const res = await post(rest as Record<string, string>);
    expect(res.status).toBe(400);
  });

  it('returns 400 for subdomain with spaces or special chars', async () => {
    const res = await post({ ...validParams, subdomain: 'my company!' });
    expect(res.status).toBe(400);
  });

  it('returns 400 for subdomain containing dots', async () => {
    const res = await post({ ...validParams, subdomain: 'my.company' });
    expect(res.status).toBe(400);
  });

  it('returns 400 for unknown client_id', async () => {
    mockSql.mockResolvedValueOnce([]);
    const res = await post(validParams);
    expect(res.status).toBe(400);
  });

  it('returns 400 when redirect_uri is not registered for the client', async () => {
    mockSql.mockResolvedValueOnce([
      { id: CLIENT_ID, redirect_uris: ['https://other.example.com/cb'] },
    ]);
    const res = await post(validParams);
    expect(res.status).toBe(400);
  });

  it('returns 400 (HTML error page) when AC DCR returns non-OK status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      text: () => Promise.resolve('Bad Request'),
    }));
    const res = await post(validParams);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain('Could not register with ActiveCampaign');
  });

  it('returns 400 (HTML error page) when AC DCR returns no client_id', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({}),
      text: () => Promise.resolve(''),
    }));
    const res = await post(validParams);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain('client_id');
  });

  it('returns 502 (HTML error page) when AC DCR throws a network error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
    const res = await post(validParams);
    expect(res.status).toBe(502);
    const text = await res.text();
    expect(text).toContain('Network error');
  });

  it('redirects to AC authorization URL on success', async () => {
    const res = await post(validParams);
    expect(res.status).toBe(302);
    const location = res.headers.get('location') ?? '';
    expect(location).toContain('https://oauth2.app-us1.com/oauth2/auth');
  });

  it('includes required OAuth params in the AC authorization redirect', async () => {
    const res = await post(validParams);
    const location = res.headers.get('location') ?? '';
    const url = new URL(location);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    expect(url.searchParams.get('state')).toBeTruthy();
    expect(url.searchParams.get('redirect_uri')).toContain('/ac/callback');
    expect(url.searchParams.get('scope')).toBeTruthy();
  });

  it('inserts a pending session in the DB on success', async () => {
    await post(validParams);
    // First call: SELECT client; second call: INSERT pending_session
    expect(mockSql).toHaveBeenCalledTimes(2);
  });

  it('accepts alphanumeric subdomains with hyphens', async () => {
    const res = await post({ ...validParams, subdomain: 'my-company-123' });
    expect(res.status).toBe(302);
  });
});
