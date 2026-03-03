import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../db/index.js', () => {
  const mockSql = vi.fn().mockResolvedValue([]);
  (mockSql as unknown as Record<string, unknown>).json = vi.fn((v: unknown) => v);
  (mockSql as unknown as Record<string, unknown>).unsafe = vi.fn().mockResolvedValue([]);
  return { sql: mockSql };
});

import { authorizeGetRoute } from '../oauth/authorize.js';
import { sql } from '../db/index.js';

const mockSql = vi.mocked(sql);

const CLIENT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const REDIRECT_URI = 'https://chatgpt.com/aip/plugin-oauth/callback';

const validParams = {
  client_id: CLIENT_ID,
  redirect_uri: REDIRECT_URI,
  response_type: 'code',
  code_challenge: 'abc123challenge',
  state: 'random-state-value',
};

function get(params: Record<string, string>) {
  const qs = new URLSearchParams(params).toString();
  return authorizeGetRoute.request(`/oauth/authorize?${qs}`);
}

beforeEach(() => {
  vi.clearAllMocks();
  mockSql.mockResolvedValue([{ id: CLIENT_ID, redirect_uris: [REDIRECT_URI] }]);
});

describe('GET /oauth/authorize', () => {
  it('returns 200 HTML form for a valid request', async () => {
    const res = await get(validParams);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('<!DOCTYPE html>');
  });

  it('returns 400 when client_id is missing', async () => {
    const { client_id: _, ...rest } = validParams;
    const res = await get(rest as Record<string, string>);
    expect(res.status).toBe(400);
  });

  it('returns 400 when redirect_uri is missing', async () => {
    const { redirect_uri: _, ...rest } = validParams;
    const res = await get(rest as Record<string, string>);
    expect(res.status).toBe(400);
  });

  it('returns 400 when response_type is not "code"', async () => {
    const res = await get({ ...validParams, response_type: 'token' });
    expect(res.status).toBe(400);
  });

  it('returns 400 when code_challenge is missing', async () => {
    const { code_challenge: _, ...rest } = validParams;
    const res = await get(rest as Record<string, string>);
    expect(res.status).toBe(400);
  });

  it('returns 400 when state is missing', async () => {
    const { state: _, ...rest } = validParams;
    const res = await get(rest as Record<string, string>);
    expect(res.status).toBe(400);
  });

  it('returns 400 for unsupported code_challenge_method', async () => {
    const res = await get({ ...validParams, code_challenge_method: 'plain' });
    expect(res.status).toBe(400);
  });

  it('accepts S256 code_challenge_method explicitly', async () => {
    const res = await get({ ...validParams, code_challenge_method: 'S256' });
    expect(res.status).toBe(200);
  });

  it('returns 400 for non-UUID client_id', async () => {
    const res = await get({ ...validParams, client_id: 'not-a-uuid' });
    expect(res.status).toBe(400);
  });

  it('returns 400 for unknown client_id', async () => {
    mockSql.mockResolvedValueOnce([]);
    const res = await get(validParams);
    expect(res.status).toBe(400);
  });

  it('returns 400 when redirect_uri is not registered for the client', async () => {
    mockSql.mockResolvedValueOnce([
      { id: CLIENT_ID, redirect_uris: ['https://other.example.com/cb'] },
    ]);
    const res = await get(validParams);
    expect(res.status).toBe(400);
  });

  it('embeds state and code_challenge URL-encoded in the returned HTML', async () => {
    const res = await get(validParams);
    const text = await res.text();
    expect(text).toContain(encodeURIComponent(validParams.state));
    expect(text).toContain(encodeURIComponent(validParams.code_challenge));
  });

  it('embeds client_id and redirect_uri URL-encoded in the returned HTML', async () => {
    const res = await get(validParams);
    const text = await res.text();
    expect(text).toContain(encodeURIComponent(CLIENT_ID));
    expect(text).toContain(encodeURIComponent(REDIRECT_URI));
  });
});
