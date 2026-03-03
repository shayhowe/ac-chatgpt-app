import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../db/index.js', () => {
  const mockSql = vi.fn().mockResolvedValue([]);
  (mockSql as unknown as Record<string, unknown>).json = vi.fn((v: unknown) => v);
  (mockSql as unknown as Record<string, unknown>).unsafe = vi.fn().mockResolvedValue([]);
  return { sql: mockSql };
});

import { app } from '../app.js';
import { sql } from '../db/index.js';

const mockSql = vi.mocked(sql);

beforeEach(() => {
  vi.clearAllMocks();
});

describe('GET /health', () => {
  it('returns 200 with status ok', async () => {
    const res = await app.request('/health');
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.status).toBe('ok');
  });
});

describe('Unknown routes', () => {
  it('returns 404 for an unknown path', async () => {
    const res = await app.request('/this-route-does-not-exist');
    expect(res.status).toBe(404);
  });
});

describe('Error handler', () => {
  it('returns 500 with internal_error when a route handler throws', async () => {
    // Trigger a route that hits the DB (GET /oauth/authorize with valid UUID client_id)
    // and make sql throw to exercise app.onError
    mockSql.mockRejectedValueOnce(new Error('DB connection lost'));

    const res = await app.request(
      '/oauth/authorize' +
        '?client_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' +
        '&redirect_uri=https://chatgpt.com/cb' +
        '&response_type=code' +
        '&code_challenge=abc' +
        '&state=xyz',
    );

    expect(res.status).toBe(500);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('internal_error');
  });
});
