# AC MCP Gateway

An OAuth 2.1-compliant gateway that enables ChatGPT to securely access ActiveCampaign accounts via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

It acts as a broker between ChatGPT and ActiveCampaign, handling OAuth authentication flows, encrypted token storage, and MCP request proxying with automatic token refresh.

## How it works

The app implements a three-legged OAuth 2.1 + PKCE flow:

1. ChatGPT initiates OAuth with this gateway
2. Gateway registers with ActiveCampaign via Dynamic Client Registration and redirects the user to AC login
3. AC returns tokens to the gateway, which encrypts and stores them, then returns an opaque token to ChatGPT
4. ChatGPT uses that token to make MCP requests; the gateway proxies them to AC, transparently refreshing AC tokens as needed

## Tech stack

- **Runtime:** Node.js 22, TypeScript (strict)
- **Framework:** [Hono](https://hono.dev/) v4
- **Database:** PostgreSQL
- **Validation:** Zod
- **Testing:** Vitest
- **Deployment:** Docker + Fly.io

## Project structure

```
src/
├── index.ts              # Entry point
├── app.ts                # Route registration
├── crypto.ts             # AES-256-GCM encryption, PKCE, token helpers
├── db/
│   ├── index.ts          # DB connection and initialization
│   └── schema.sql        # Table definitions
├── oauth/
│   ├── metadata.ts       # RFC 8414 / RFC 9728 discovery endpoints
│   ├── register.ts       # Dynamic Client Registration
│   ├── authorize.ts      # Consent form (GET)
│   ├── authorize-submit.ts # Subdomain processing, AC DCR (POST)
│   ├── ac-callback.ts    # AC redirect handler, code exchange
│   └── token.ts          # Issues gateway access token to ChatGPT
├── mcp/
│   └── proxy.ts          # Authenticated MCP proxy with token refresh
└── views/
    └── consent.html      # Subdomain entry form
```

## Setup

### Prerequisites

- Node.js 22+
- PostgreSQL 12+

### Environment variables

Copy `.env.example` to `.env` and fill in the values:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `BASE_URL` | Public URL of this gateway, no trailing slash (e.g. `https://ac-mcp.fly.dev`) |
| `DATABASE_URL` | PostgreSQL connection string |
| `ENCRYPTION_KEY` | 32-byte AES key, base64-encoded — generate with `openssl rand -base64 32` |
| `PORT` | Server port (default: `3000`) |

### Install and run

```bash
npm install

# Development (watch mode)
npm run dev

# Production
npm run build
npm start
```

### Other scripts

```bash
npm run typecheck       # Type-check without emitting
npm test                # Run tests once
npm run test:watch      # Run tests in watch mode
npm run test:coverage   # Run tests with coverage report
```

## Deployment (Fly.io)

```bash
# First time
fly launch
fly postgres attach <postgres-app-name>
fly secrets set ENCRYPTION_KEY=$(openssl rand -base64 32)

# Deploy
fly deploy
```

The app auto-scales to zero when idle. Health checks hit `GET /health`.

## API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 OAuth metadata |
| `GET` | `/.well-known/oauth-protected-resource` | RFC 9728 protected resource metadata |
| `POST` | `/oauth/register` | Dynamic Client Registration |
| `GET` | `/oauth/authorize` | Show consent / subdomain form |
| `POST` | `/oauth/authorize` | Process subdomain, initiate AC OAuth |
| `GET` | `/ac/callback` | Receive AC auth code, exchange for tokens |
| `POST` | `/oauth/token` | Issue gateway token to ChatGPT |
| `POST` | `/mcp` | Proxy authenticated MCP requests to AC |
| `GET` | `/health` | Health check |
