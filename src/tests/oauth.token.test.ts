import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../db/index.js', () => {
  const mockSql = vi.fn().mockResolvedValue([]);
  (mockSql as unknown as Record<string, unknown>).json = vi.fn((v: unknown) => v);
  (mockSql as unknown as Record<string, unknown>).unsafe = vi.fn().mockResolvedValue([]);
  return { sql: mockSql };
});

import { tokenRoute } from '../oauth/token.js';
import { sql } from '../db/index.js';
import { generateCodeVerifier, deriveCodeChallenge } from '../crypto.js';

const mockSql = vi.mocked(sql);

const VERIFIER = generateCodeVerifier();
const CHALLENGE = deriveCodeChallenge(VERIFIER);
const CLIENT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const USER_ID = 'ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb';
const TEST_CODE = 'test-auth-code-1234567890abcdef';

const validCodeRow = {
  code: TEST_CODE,
  user_id: USER_ID,
  our_client_id: CLIENT_ID,
  chatgpt_redirect_uri: 'https://chatgpt.com/aip/plugin-oauth/callback',
  chatgpt_code_challenge: CHALLENGE,
  expires_at: new Date(Date.now() + 10 * 60 * 1000),
};

function postForm(params: Record<string, string>) {
  return tokenRoute.request('/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('POST /oauth/token', () => {
  it('returns access_token for a valid code exchange', async () => {
    mockSql
      .mockResolvedValueOnce([validCodeRow]) // SELECT code
      .mockResolvedValueOnce([])             // DELETE code
      .mockResolvedValueOnce([]);            // UPDATE session

    const res = await postForm({
      grant_type: 'authorization_code',
      code: TEST_CODE,
      code_verifier: VERIFIER,
      client_id: CLIENT_ID,
    });

    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.access_token).toBeTruthy();
    expect(typeof body.access_token).toBe('string');
    expect(body.token_type).toBe('bearer');
  });

  it('also accepts JSON content-type', async () => {
    mockSql
      .mockResolvedValueOnce([validCodeRow])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    const res = await tokenRoute.request('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: TEST_CODE,
        code_verifier: VERIFIER,
        client_id: CLIENT_ID,
      }),
    });

    expect(res.status).toBe(200);
  });

  it('returns 400 for unsupported grant_type', async () => {
    const res = await postForm({ grant_type: 'client_credentials' });
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('unsupported_grant_type');
  });

  it('returns 400 when code is missing', async () => {
    const res = await postForm({ grant_type: 'authorization_code', code_verifier: VERIFIER, client_id: CLIENT_ID });
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_request');
  });

  it('returns 400 when code_verifier is missing', async () => {
    const res = await postForm({ grant_type: 'authorization_code', code: TEST_CODE, client_id: CLIENT_ID });
    expect(res.status).toBe(400);
  });

  it('returns 400 for unsupported content-type', async () => {
    const res = await tokenRoute.request('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: 'grant_type=authorization_code',
    });
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_request');
  });

  it('returns 400 when code is not found / expired', async () => {
    mockSql.mockResolvedValueOnce([]); // no row found

    const res = await postForm({
      grant_type: 'authorization_code',
      code: 'nonexistent-code',
      code_verifier: VERIFIER,
      client_id: CLIENT_ID,
    });

    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_grant');
  });

  it('returns 400 when client_id does not match', async () => {
    mockSql.mockResolvedValueOnce([validCodeRow]);

    const res = await postForm({
      grant_type: 'authorization_code',
      code: TEST_CODE,
      code_verifier: VERIFIER,
      client_id: 'wrong-client-id',
    });

    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_client');
  });

  it('returns 400 when PKCE verification fails', async () => {
    mockSql.mockResolvedValueOnce([validCodeRow]);

    const res = await postForm({
      grant_type: 'authorization_code',
      code: TEST_CODE,
      code_verifier: 'wrong-verifier-that-does-not-match',
      client_id: CLIENT_ID,
    });

    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_grant');
    expect(String(body.error_description)).toContain('PKCE');
  });

  it('deletes the code after successful exchange (one-time use)', async () => {
    mockSql
      .mockResolvedValueOnce([validCodeRow])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    await postForm({
      grant_type: 'authorization_code',
      code: TEST_CODE,
      code_verifier: VERIFIER,
      client_id: CLIENT_ID,
    });

    // Second call: sql was called 3 times total (SELECT, DELETE, UPDATE)
    expect(mockSql).toHaveBeenCalledTimes(3);
  });
});
