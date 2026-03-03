import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { metadataRoutes } from '../oauth/metadata.js';

describe('GET /.well-known/oauth-protected-resource', () => {
  it('returns 200 with correct shape', async () => {
    const res = await metadataRoutes.request('/.well-known/oauth-protected-resource');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/application\/json/);

    const body = await res.json() as Record<string, unknown>;
    expect(body.resource).toBe('http://localhost:3000/mcp');
    expect(body.authorization_servers).toEqual(['http://localhost:3000']);
    expect(body.scopes_supported).toContain('mcp');
    expect(body.bearer_methods_supported).toContain('header');
  });
});

describe('GET /.well-known/oauth-authorization-server', () => {
  it('returns 200 with all required RFC 8414 fields', async () => {
    const res = await metadataRoutes.request('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);

    const body = await res.json() as Record<string, unknown>;
    expect(body.issuer).toBe('http://localhost:3000');
    expect(body.authorization_endpoint).toBe('http://localhost:3000/oauth/authorize');
    expect(body.token_endpoint).toBe('http://localhost:3000/oauth/token');
    expect(body.registration_endpoint).toBe('http://localhost:3000/oauth/register');
    expect(body.response_types_supported).toContain('code');
    expect(body.grant_types_supported).toContain('authorization_code');
    expect(body.code_challenge_methods_supported).toContain('S256');
    expect(body.token_endpoint_auth_methods_supported).toContain('none');
  });

  it('returns JSON content-type', async () => {
    const res = await metadataRoutes.request('/.well-known/oauth-authorization-server');
    expect(res.headers.get('content-type')).toMatch(/application\/json/);
  });
});

describe('GET /.well-known/oauth-authorization-server/mcp (ChatGPT alias)', () => {
  it('returns the same body as the standard path', async () => {
    const standard = await (await metadataRoutes.request('/.well-known/oauth-authorization-server')).json();
    const alias = await (await metadataRoutes.request('/.well-known/oauth-authorization-server/mcp')).json();
    expect(alias).toEqual(standard);
  });

  it('returns 200', async () => {
    const res = await metadataRoutes.request('/.well-known/oauth-authorization-server/mcp');
    expect(res.status).toBe(200);
  });
});

describe('BASE_URL customisation', () => {
  const originalBaseUrl = process.env.BASE_URL;

  beforeEach(() => {
    process.env.BASE_URL = 'https://custom.example.com';
  });

  afterEach(() => {
    process.env.BASE_URL = originalBaseUrl;
  });

  it('reflects custom BASE_URL in issuer', async () => {
    const res = await metadataRoutes.request('/.well-known/oauth-authorization-server');
    const body = await res.json() as Record<string, unknown>;
    expect(body.issuer).toBe('https://custom.example.com');
    expect(body.authorization_endpoint).toContain('https://custom.example.com');
  });
});
