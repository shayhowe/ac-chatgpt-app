-- Our OAuth clients (ChatGPT registers one per session via DCR)
CREATE TABLE IF NOT EXISTS our_clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  redirect_uris JSONB NOT NULL,
  client_name TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Pending OAuth sessions (between our /authorize and /ac/callback)
CREATE TABLE IF NOT EXISTS pending_sessions (
  state TEXT PRIMARY KEY,              -- our random state (used for AC leg)
  our_client_id UUID NOT NULL REFERENCES our_clients(id),
  chatgpt_redirect_uri TEXT NOT NULL,
  chatgpt_code_challenge TEXT NOT NULL,
  chatgpt_state TEXT NOT NULL,         -- original state ChatGPT sent us (pass back on redirect)
  ac_subdomain TEXT NOT NULL,
  ac_client_id TEXT NOT NULL,
  ac_code_verifier TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

-- Our auth codes (after AC OAuth completes, before ChatGPT exchanges)
CREATE TABLE IF NOT EXISTS our_codes (
  code TEXT PRIMARY KEY,
  user_id UUID NOT NULL,
  our_client_id UUID NOT NULL,
  chatgpt_redirect_uri TEXT NOT NULL,
  chatgpt_code_challenge TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

-- User sessions: our tokens + encrypted AC tokens
CREATE TABLE IF NOT EXISTS user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  our_token_hash TEXT UNIQUE NOT NULL,
  ac_subdomain TEXT NOT NULL,
  ac_client_id TEXT NOT NULL,
  ac_access_token_enc TEXT NOT NULL,
  ac_refresh_token_enc TEXT NOT NULL,
  ac_token_expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_used_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash ON user_sessions(our_token_hash);
