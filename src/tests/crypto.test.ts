import { describe, it, expect } from 'vitest';
import {
  encrypt,
  decrypt,
  generateToken,
  generateState,
  hashToken,
  generateCodeVerifier,
  deriveCodeChallenge,
  validatePkce,
} from '../crypto.js';

describe('AES-256-GCM encrypt/decrypt', () => {
  it('round-trips plaintext', () => {
    const plain = 'hello world';
    expect(decrypt(encrypt(plain))).toBe(plain);
  });

  it('round-trips empty string', () => {
    expect(decrypt(encrypt(''))).toBe('');
  });

  it('round-trips unicode', () => {
    const plain = '日本語テスト 🔐';
    expect(decrypt(encrypt(plain))).toBe(plain);
  });

  it('produces different ciphertexts each call (random IV)', () => {
    const plain = 'same input';
    expect(encrypt(plain)).not.toBe(encrypt(plain));
  });

  it('throws on corrupted auth tag', () => {
    const enc = encrypt('secret');
    const buf = Buffer.from(enc, 'base64');
    // Flip last byte (auth tag region)
    buf[buf.length - 1] ^= 0xff;
    expect(() => decrypt(buf.toString('base64'))).toThrow();
  });

  it('throws on corrupted IV', () => {
    const enc = encrypt('secret');
    const buf = Buffer.from(enc, 'base64');
    // Flip first byte (IV region)
    buf[0] ^= 0xff;
    expect(() => decrypt(buf.toString('base64'))).toThrow();
  });

  it('throws on input that is too short', () => {
    const tooShort = Buffer.alloc(10).toString('base64');
    expect(() => decrypt(tooShort)).toThrow('too short');
  });

  it('throws on garbage input', () => {
    expect(() => decrypt('not-valid-ciphertext')).toThrow();
  });
});

describe('generateToken', () => {
  it('returns a 64-char hex string', () => {
    expect(generateToken()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns unique values on successive calls', () => {
    expect(generateToken()).not.toBe(generateToken());
  });
});

describe('generateState', () => {
  it('returns a non-empty base64url string', () => {
    const state = generateState();
    expect(state.length).toBeGreaterThan(0);
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('returns unique values on successive calls', () => {
    expect(generateState()).not.toBe(generateState());
  });
});

describe('hashToken', () => {
  it('is deterministic', () => {
    expect(hashToken('token')).toBe(hashToken('token'));
  });

  it('returns a 64-char hex string (SHA-256)', () => {
    expect(hashToken('anything')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces different hashes for different inputs', () => {
    expect(hashToken('a')).not.toBe(hashToken('b'));
  });
});

describe('PKCE', () => {
  it('generateCodeVerifier returns a base64url string of length 43', () => {
    // 32 bytes → 43 base64url chars (no padding)
    const verifier = generateCodeVerifier();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('generateCodeVerifier returns unique values', () => {
    expect(generateCodeVerifier()).not.toBe(generateCodeVerifier());
  });

  it('matches RFC 7636 Appendix B test vector', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const expectedChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    expect(deriveCodeChallenge(verifier)).toBe(expectedChallenge);
  });

  it('validatePkce returns true for a matching pair', () => {
    const verifier = generateCodeVerifier();
    const challenge = deriveCodeChallenge(verifier);
    expect(validatePkce(verifier, challenge)).toBe(true);
  });

  it('validatePkce returns false for a wrong verifier', () => {
    const verifier = generateCodeVerifier();
    const challenge = deriveCodeChallenge(verifier);
    expect(validatePkce('wrong-verifier', challenge)).toBe(false);
  });

  it('validatePkce returns false for empty strings', () => {
    expect(validatePkce('', '')).toBe(false);
  });

  it('validatePkce returns false when verifier is one char off', () => {
    const verifier = generateCodeVerifier();
    const challenge = deriveCodeChallenge(verifier);
    const tampered = verifier.slice(0, -1) + (verifier.endsWith('a') ? 'b' : 'a');
    expect(validatePkce(tampered, challenge)).toBe(false);
  });
});
