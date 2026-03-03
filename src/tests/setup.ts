// Global test setup — ensure test env vars are set, overriding any local .env file.
// vitest.config.ts sets these via test.env, but a local .env file can take priority.
// Explicitly setting them here in setupFiles guarantees the test values win.
process.env.ENCRYPTION_KEY = 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=';
process.env.DATABASE_URL = 'postgres://fake:fake@localhost:5432/fake';
process.env.BASE_URL = 'http://localhost:3000';
