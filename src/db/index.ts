import postgres from 'postgres';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  throw new Error('DATABASE_URL environment variable is required');
}

// Fly's internal Postgres (.flycast / .internal) runs over WireGuard — no SSL needed.
// External hosts (e.g. Supabase, RDS) still use SSL.
function resolveSsl(url: string): boolean | { rejectUnauthorized: boolean } {
  try {
    const host = new URL(url).hostname;
    if (host === 'localhost' || host === '127.0.0.1' ||
        host.endsWith('.internal') || host.endsWith('.flycast')) {
      return false;
    }
  } catch { /* fall through */ }
  return { rejectUnauthorized: false };
}

export const sql = postgres(DATABASE_URL, {
  max: 10,
  idle_timeout: 30,
  connect_timeout: 10,
  ssl: resolveSsl(DATABASE_URL),
});

export async function initDb(): Promise<void> {
  const schema = readFileSync(join(__dirname, 'schema.sql'), 'utf-8');
  await sql.unsafe(schema);
  console.log('Database schema initialized');
}

export type OurClient = {
  id: string;
  redirect_uris: string[];
  client_name: string | null;
  created_at: Date;
};

export type PendingSession = {
  state: string;
  our_client_id: string;
  chatgpt_redirect_uri: string;
  chatgpt_code_challenge: string;
  ac_subdomain: string;
  ac_client_id: string;
  ac_code_verifier: string;
  expires_at: Date;
};

export type OurCode = {
  code: string;
  user_id: string;
  our_client_id: string;
  chatgpt_redirect_uri: string;
  chatgpt_code_challenge: string;
  expires_at: Date;
};

export type UserSession = {
  id: string;
  our_token_hash: string;
  ac_subdomain: string;
  ac_client_id: string;
  ac_access_token_enc: string;
  ac_refresh_token_enc: string;
  ac_token_expires_at: Date;
  created_at: Date;
  last_used_at: Date;
};
