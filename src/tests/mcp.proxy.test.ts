import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../db/index.js', () => {
  const mockSql = vi.fn().mockResolvedValue([]);
  (mockSql as unknown as Record<string, unknown>).json = vi.fn((v: unknown) => v);
  (mockSql as unknown as Record<string, unknown>).unsafe = vi.fn().mockResolvedValue([]);
  return { sql: mockSql };
});

import { mcpProxyRoute } from '../mcp/proxy.js';
import { sql } from '../db/index.js';
import { encrypt, hashToken } from '../crypto.js';
import type { UserSession } from '../db/index.js';

const mockSql = vi.mocked(sql);

const BEARER_TOKEN = 'valid-test-bearer-token-1234567890ab';
const TOKEN_HASH = hashToken(BEARER_TOKEN);
const FAKE_AC_TOKEN = 'fake-ac-access-token';

function makeSession(overrides: Partial<UserSession> = {}): UserSession {
  return {
    id: 'session-uuid-1234',
    our_token_hash: TOKEN_HASH,
    ac_subdomain: 'mycompany',
    ac_client_id: 'ac-client-id',
    ac_access_token_enc: encrypt(FAKE_AC_TOKEN),
    ac_refresh_token_enc: encrypt(''),
    ac_token_expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000), // 2 hours from now
    created_at: new Date(),
    last_used_at: new Date(),
    ...overrides,
  };
}

function mockFetchOk(body = '{"jsonrpc":"2.0","result":{}}') {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    headers: new Headers({ 'content-type': 'application/json' }),
    arrayBuffer: () => Promise.resolve(Buffer.from(body).buffer),
  });
}

function postMcp(token?: string) {
  return mcpProxyRoute.request('/mcp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal('fetch', mockFetchOk());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('GET /mcp', () => {
  it('returns 401 with WWW-Authenticate to trigger OAuth discovery', async () => {
    const res = await mcpProxyRoute.request('/mcp');
    expect(res.status).toBe(401);
    const wwwAuth = res.headers.get('www-authenticate') ?? '';
    expect(wwwAuth).toContain('Bearer');
    expect(wwwAuth).toContain('resource_metadata=');
  });
});

describe('POST /mcp — auth header validation', () => {
  it('returns 401 with no Authorization header', async () => {
    const res = await postMcp();
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBeTruthy();
  });

  it('returns 401 for non-Bearer auth scheme', async () => {
    const res = await mcpProxyRoute.request('/mcp', {
      method: 'POST',
      headers: { Authorization: 'Basic dXNlcjpwYXNz' },
    });
    expect(res.status).toBe(401);
  });
});

describe('POST /mcp — token lookup', () => {
  it('returns 401 invalid_token when token not found in DB', async () => {
    mockSql.mockResolvedValueOnce([]); // no session found

    const res = await postMcp(BEARER_TOKEN);
    expect(res.status).toBe(401);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_token');
    const wwwAuth = res.headers.get('www-authenticate') ?? '';
    expect(wwwAuth).toContain('error="invalid_token"');
  });
});

describe('POST /mcp — successful proxy', () => {
  it('returns 200 and proxies response from AC', async () => {
    mockSql
      .mockResolvedValueOnce([makeSession()]) // session lookup
      .mockResolvedValueOnce([]);             // last_used_at update (fire-and-forget)

    const res = await postMcp(BEARER_TOKEN);
    expect(res.status).toBe(200);
  });

  it('forwards request to correct AC MCP URL with Bearer token', async () => {
    const mockFetch = mockFetchOk();
    vi.stubGlobal('fetch', mockFetch);

    mockSql
      .mockResolvedValueOnce([makeSession()])
      .mockResolvedValueOnce([]);

    await postMcp(BEARER_TOKEN);

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://mycompany.activehosted.com/api/agents/mcp/http');
    expect((init.headers as Record<string, string>)['Authorization']).toBe(`Bearer ${FAKE_AC_TOKEN}`);
  });

  it('always sends correct Accept header to AC (strict SSE check)', async () => {
    const mockFetch = mockFetchOk();
    vi.stubGlobal('fetch', mockFetch);

    mockSql
      .mockResolvedValueOnce([makeSession()])
      .mockResolvedValueOnce([]);

    await postMcp(BEARER_TOKEN);

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['Accept']).toBe('application/json, text/event-stream');
  });
});

describe('POST /mcp — AC error handling', () => {
  it('returns 401 when AC returns 401 (token revoked)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers(),
      arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    }));

    mockSql
      .mockResolvedValueOnce([makeSession()])
      .mockResolvedValueOnce([]);

    const res = await postMcp(BEARER_TOKEN);
    expect(res.status).toBe(401);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_token');
  });

  it('returns 502 when fetch throws (network error)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));

    mockSql
      .mockResolvedValueOnce([makeSession()])
      .mockResolvedValueOnce([]);

    const res = await postMcp(BEARER_TOKEN);
    expect(res.status).toBe(502);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('bad_gateway');
  });

  it('returns 500 when AC token decryption fails', async () => {
    mockSql.mockResolvedValueOnce([
      makeSession({ ac_access_token_enc: 'garbage-not-valid-base64-ciphertext!!' }),
    ]);

    const res = await postMcp(BEARER_TOKEN);
    expect(res.status).toBe(500);
  });
});

describe('POST /mcp — token refresh', () => {
  it('refreshes AC token when near expiry and proxies with new token', async () => {
    const NEW_AC_TOKEN = 'new-refreshed-ac-token';
    const nearExpiry = makeSession({
      ac_refresh_token_enc: encrypt('valid-refresh-token'),
      ac_token_expires_at: new Date(Date.now() + 2 * 60 * 1000), // 2 min — within 5-min buffer
    });

    mockSql
      .mockResolvedValueOnce([nearExpiry]) // session lookup
      .mockResolvedValueOnce([makeSession({ // UPDATE returning refreshed session
        ac_access_token_enc: encrypt(NEW_AC_TOKEN),
        ac_token_expires_at: new Date(Date.now() + 60 * 60 * 1000),
      })])
      .mockResolvedValueOnce([]); // last_used_at update

    const mockFetch = vi.fn()
      .mockResolvedValueOnce({ // AC token refresh call
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          access_token: NEW_AC_TOKEN,
          expires_in: 3600,
        }),
        text: () => Promise.resolve(''),
      })
      .mockResolvedValueOnce({ // AC MCP proxy call
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });

    vi.stubGlobal('fetch', mockFetch);

    const res = await postMcp(BEARER_TOKEN);
    expect(res.status).toBe(200);

    // Second fetch call should use the new token
    const [, mcpInit] = mockFetch.mock.calls[1] as [string, RequestInit];
    expect((mcpInit.headers as Record<string, string>)['Authorization']).toBe(`Bearer ${NEW_AC_TOKEN}`);
  });

  it('returns 401 when token is near expiry and refresh fails', async () => {
    const nearExpiry = makeSession({
      ac_refresh_token_enc: encrypt('refresh-token'),
      ac_token_expires_at: new Date(Date.now() + 2 * 60 * 1000),
    });

    mockSql.mockResolvedValueOnce([nearExpiry]);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      text: () => Promise.resolve('invalid_grant'),
    }));

    const res = await postMcp(BEARER_TOKEN);
    expect(res.status).toBe(401);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_token');
  });

  it('returns 401 when near expiry but no refresh token stored', async () => {
    const nearExpiry = makeSession({
      ac_refresh_token_enc: encrypt(''), // empty = no refresh token
      ac_token_expires_at: new Date(Date.now() + 2 * 60 * 1000),
    });

    mockSql.mockResolvedValueOnce([nearExpiry]);

    const res = await postMcp(BEARER_TOKEN);
    expect(res.status).toBe(401);
  });
});
