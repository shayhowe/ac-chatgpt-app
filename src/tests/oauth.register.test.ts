import { describe, it, expect, vi, beforeEach } from 'vitest';

// Must be hoisted before any imports that use the DB
vi.mock('../db/index.js', () => {
  const mockSql = vi.fn().mockResolvedValue([]);
  (mockSql as unknown as Record<string, unknown>).json = vi.fn((v: unknown) => v);
  (mockSql as unknown as Record<string, unknown>).unsafe = vi.fn().mockResolvedValue([]);
  return { sql: mockSql };
});

import { registerRoute } from '../oauth/register.js';
import { sql } from '../db/index.js';

const mockSql = vi.mocked(sql);

const CHATGPT_REDIRECT = 'https://chatgpt.com/aip/plugin-oauth/callback';

function post(body: unknown) {
  return registerRoute.request('/oauth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  // Default: DB returns a new client row
  mockSql.mockResolvedValue([
    {
      id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      redirect_uris: [CHATGPT_REDIRECT],
      client_name: 'Test Client',
      created_at: new Date(),
    },
  ]);
});

describe('POST /oauth/register', () => {
  it('returns 201 with client_id for a valid request', async () => {
    const res = await post({ redirect_uris: [CHATGPT_REDIRECT], client_name: 'Test' });
    expect(res.status).toBe(201);
    const body = await res.json() as Record<string, unknown>;
    expect(body.client_id).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    expect(body.grant_types).toContain('authorization_code');
    expect(body.token_endpoint_auth_method).toBe('none');
  });

  it('returns 201 without optional client_name', async () => {
    mockSql.mockResolvedValueOnce([
      { id: 'new-uuid', redirect_uris: [CHATGPT_REDIRECT], client_name: null, created_at: new Date() },
    ]);
    const res = await post({ redirect_uris: [CHATGPT_REDIRECT] });
    expect(res.status).toBe(201);
  });

  it('allows platform.openai.com redirect URIs', async () => {
    mockSql.mockResolvedValueOnce([
      { id: 'uuid', redirect_uris: ['https://platform.openai.com/callback'], client_name: null, created_at: new Date() },
    ]);
    const res = await post({ redirect_uris: ['https://platform.openai.com/callback'] });
    expect(res.status).toBe(201);
  });

  it('allows localhost redirect URIs', async () => {
    mockSql.mockResolvedValueOnce([
      { id: 'uuid', redirect_uris: ['http://localhost:3000/cb'], client_name: null, created_at: new Date() },
    ]);
    const res = await post({ redirect_uris: ['http://localhost:3000/cb'] });
    expect(res.status).toBe(201);
  });

  it('returns 400 for a disallowed redirect URI', async () => {
    const res = await post({ redirect_uris: ['https://evil.com/steal-tokens'] });
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_redirect_uri');
  });

  it('returns 400 when redirect_uris is missing', async () => {
    const res = await post({ client_name: 'No URIs' });
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_client_metadata');
  });

  it('returns 400 when redirect_uris is empty array', async () => {
    const res = await post({ redirect_uris: [] });
    expect(res.status).toBe(400);
  });

  it('returns 400 for invalid URL in redirect_uris', async () => {
    const res = await post({ redirect_uris: ['not-a-url'] });
    expect(res.status).toBe(400);
  });

  it('returns 400 for non-JSON body', async () => {
    const res = await registerRoute.request('/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'this is not json',
    });
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('invalid_request');
  });

  it('inserts into DB with sql.json for redirect_uris', async () => {
    await post({ redirect_uris: [CHATGPT_REDIRECT] });
    expect(mockSql).toHaveBeenCalledOnce();
  });

  it('returns redirect_uris from DB row (not hardcoded)', async () => {
    const uris = [CHATGPT_REDIRECT, 'https://chatgpt.com/other'];
    mockSql.mockResolvedValueOnce([
      { id: 'x', redirect_uris: uris, client_name: null, created_at: new Date() },
    ]);
    const res = await post({ redirect_uris: uris });
    const body = await res.json() as Record<string, unknown>;
    expect(body.redirect_uris).toEqual(uris);
  });
});
