import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  createHash,
} from 'crypto';

// ── Encryption key ────────────────────────────────────────────────────────────

function getEncryptionKey(): Buffer {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) throw new Error('ENCRYPTION_KEY environment variable is required');
  const buf = Buffer.from(key, 'base64');
  if (buf.length !== 32) {
    throw new Error('ENCRYPTION_KEY must be a 32-byte value encoded as base64');
  }
  return buf;
}

// ── AES-256-GCM encrypt/decrypt ───────────────────────────────────────────────

/**
 * Encrypt a plaintext string.
 * Returns a base64 string containing: iv (12 bytes) || ciphertext || authTag (16 bytes)
 */
export function encrypt(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, encrypted, authTag]).toString('base64');
}

/**
 * Decrypt a base64 string produced by encrypt().
 */
export function decrypt(ciphertext: string): string {
  const key = getEncryptionKey();
  const buf = Buffer.from(ciphertext, 'base64');

  if (buf.length < 12 + 16) {
    throw new Error('Invalid ciphertext: too short');
  }

  const iv = buf.subarray(0, 12);
  const authTag = buf.subarray(buf.length - 16);
  const encrypted = buf.subarray(12, buf.length - 16);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ── Token generation & hashing ────────────────────────────────────────────────

/** Generate a cryptographically random opaque token (hex, 32 bytes = 64 hex chars). */
export function generateToken(): string {
  return randomBytes(32).toString('hex');
}

/** Generate a random state value (URL-safe base64, 24 bytes). */
export function generateState(): string {
  return randomBytes(24).toString('base64url');
}

/** SHA-256 hash of a token for safe storage. Returns hex string. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ── PKCE ──────────────────────────────────────────────────────────────────────

/** Generate a PKCE code_verifier (43–128 chars, URL-safe base64). */
export function generateCodeVerifier(): string {
  // 32 bytes → 43 base64url chars (well within 128-char limit)
  return randomBytes(32).toString('base64url');
}

/** Derive the code_challenge from a verifier using S256 method. */
export function deriveCodeChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Validate that SHA256(code_verifier) === code_challenge (base64url, S256).
 * Returns true if valid.
 */
export function validatePkce(codeVerifier: string, codeChallenge: string): boolean {
  const expected = deriveCodeChallenge(codeVerifier);
  // Constant-time comparison to prevent timing attacks
  if (expected.length !== codeChallenge.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ codeChallenge.charCodeAt(i);
  }
  return diff === 0;
}
