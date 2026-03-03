import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../db/index.js', () => {
  const mockSql = vi.fn().mockResolvedValue([]);
  (mockSql as unknown as Record<string, unknown>).json = vi.fn((v: unknown) => v);
  (mockSql as unknown as Record<string, unknown>).unsafe = vi.fn().mockResolvedValue([]);
  return { sql: mockSql };
});

import { acCallbackRoute } from '../oauth/ac-callback.js';
import { sql } from '../db/index.js';

const mockSql = vi.mocked(sql);

const USER_ID = 'ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb';
const CLIENT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const CHATGPT_REDIRECT = 'https://chatgpt.com/aip/plugin-oauth/callback';
const AC_STATE = 'our-ac-state-value';

function makePendingSession(overrides = {}) {
  return {
    state: AC_STATE,
    our_client_id: CLIENT_ID,
    chatgpt_redirect_uri: CHATGPT_REDIRECT,
    chatgpt_code_challenge: 'some-challenge',
    chatgpt_state: 'chatgpt-original-state',
    ac_subdomain: 'mycompany',
    ac_client_id: 'ac-client-id',
    ac_code_verifier: 'ac-verifier',
    expires_at: new Date(Date.now() + 10 * 60 * 1000),
    ...overrides,
  };
}

function mockAcTokenOk(tokens: Record<string, unknown> = {}) {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: () =>
      Promise.resolve({
        access_token: 'ac-access-token',
        refresh_token: 'ac-refresh-token',
        expires_in: 3600,
        ...tokens,
      }),
    text: () => Promise.resolve(''),
  });
}

function get(params: Record<string, string>) {
  const qs = new URLSearchParams(params).toString();
  return acCallbackRoute.request(`/ac/callback?${qs}`);
}

// Set up a successful 4-call DB sequence
function mockSuccessDb() {
  mockSql
    .mockResolvedValueOnce([makePendingSession()]) // SELECT pending_session
    .mockResolvedValueOnce([])                     // DELETE pending_session
    .mockResolvedValueOnce([{ id: USER_ID }])      // INSERT user_sessions RETURNING id
    .mockResolvedValueOnce([]);                    // INSERT our_codes
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal('fetch', mockAcTokenOk());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('GET /ac/callback — AC error params', () => {
  it('returns 400 HTML when AC returns an error query param with description', async () => {
    const res = await get({ error: 'access_denied', error_description: 'User denied access' });
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain('User denied access');
  });

  it('returns 400 HTML when error is present without description', async () => {
    const res = await get({ error: 'server_error' });
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain('server_error');
  });
});

describe('GET /ac/callback — missing params', () => {
  it('returns 400 HTML when code is missing', async () => {
    const res = await get({ state: AC_STATE });
    expect(res.status).toBe(400);
  });

  it('returns 400 HTML when state is missing', async () => {
    const res = await get({ code: 'some-ac-code' });
    expect(res.status).toBe(400);
  });
});

describe('GET /ac/callback — session lookup', () => {
  it('returns 400 HTML when pending session is not found or expired', async () => {
    mockSql.mockResolvedValueOnce([]); // no session found
    const res = await get({ code: 'ac-code', state: 'unknown-state' });
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain('expired');
  });
});

describe('GET /ac/callback — AC token exchange failures', () => {
  it('returns 502 HTML when AC token endpoint returns non-OK status', async () => {
    mockSql
      .mockResolvedValueOnce([makePendingSession()])
      .mockResolvedValueOnce([]);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      text: () => Promise.resolve('invalid_grant'),
    }));
    const res = await get({ code: 'ac-code', state: AC_STATE });
    expect(res.status).toBe(502);
  });

  it('returns 502 HTML when AC token response has no access_token', async () => {
    mockSql
      .mockResolvedValueOnce([makePendingSession()])
      .mockResolvedValueOnce([]);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ refresh_token: 'rt' }), // no access_token
      text: () => Promise.resolve(''),
    }));
    const res = await get({ code: 'ac-code', state: AC_STATE });
    expect(res.status).toBe(502);
  });

  it('returns 502 HTML when AC token exchange throws a network error', async () => {
    mockSql
      .mockResolvedValueOnce([makePendingSession()])
      .mockResolvedValueOnce([]);
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
    const res = await get({ code: 'ac-code', state: AC_STATE });
    expect(res.status).toBe(502);
  });
});

describe('GET /ac/callback — success', () => {
  it('redirects to ChatGPT redirect URI with code and original state', async () => {
    mockSuccessDb();
    const res = await get({ code: 'ac-code', state: AC_STATE });
    expect(res.status).toBe(302);
    const location = res.headers.get('location') ?? '';
    expect(location).toContain(CHATGPT_REDIRECT);
    const url = new URL(location);
    expect(url.searchParams.get('code')).toBeTruthy();
    expect(url.searchParams.get('state')).toBe('chatgpt-original-state');
  });

  it('makes 4 DB calls: SELECT session, DELETE session, INSERT user_session, INSERT code', async () => {
    mockSuccessDb();
    await get({ code: 'ac-code', state: AC_STATE });
    expect(mockSql).toHaveBeenCalledTimes(4);
  });

  it('handles missing refresh_token from AC (succeeds with empty string)', async () => {
    vi.stubGlobal('fetch', mockAcTokenOk({ refresh_token: undefined }));
    mockSuccessDb();
    const res = await get({ code: 'ac-code', state: AC_STATE });
    expect(res.status).toBe(302);
  });

  it('handles missing expires_in from AC (defaults to 3600)', async () => {
    vi.stubGlobal('fetch', mockAcTokenOk({ expires_in: undefined }));
    mockSuccessDb();
    const res = await get({ code: 'ac-code', state: AC_STATE });
    expect(res.status).toBe(302);
  });
});
