import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    setupFiles: ['./src/tests/setup.ts'],
    env: {
      // 32 bytes of 0x61 ('a') encoded as base64 — used as a stable test key
      ENCRYPTION_KEY: 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=',
      DATABASE_URL: 'postgres://fake:fake@localhost:5432/fake',
      BASE_URL: 'http://localhost:3000',
    },
  },
  resolve: {
    conditions: ['node', 'import', 'default'],
  },
});
