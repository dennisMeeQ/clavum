import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer } from 'node:http';
import { ed25519, fromBase64Url, signatures } from '@clavum/crypto';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { SignedFetchConfig } from '../../src/http.js';
import {
  AuthError,
  ConflictError,
  NotFoundError,
  ServerError,
  signedFetch,
} from '../../src/http.js';

let serverPort: number;
let server: ReturnType<typeof createServer>;
let lastHeaders: Record<string, string | string[] | undefined> = {};
let lastBody = '';
let responseStatus = 200;
let responseBody = '{}';

const keys = ed25519.generateKeypair();
const config: SignedFetchConfig = {
  agentId: 'test-agent-123',
  ed25519Priv: keys.privateKey,
  serverUrl: '', // set in beforeAll
};

beforeAll(async () => {
  server = createServer((req: IncomingMessage, res: ServerResponse) => {
    lastHeaders = req.headers;
    let body = '';
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      lastBody = body;
      res.writeHead(responseStatus, { 'Content-Type': 'application/json' });
      res.end(responseBody);
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        serverPort = addr.port;
      }
      config.serverUrl = `http://localhost:${serverPort}`;
      resolve();
    });
  });
});

afterEach(() => {
  responseStatus = 200;
  responseBody = '{}';
});

afterAll(() => {
  server.close();
});

describe('signed HTTP client', () => {
  it('should set correct auth headers', async () => {
    responseStatus = 200;
    responseBody = JSON.stringify({ ok: true });

    await signedFetch('POST', '/api/test', '{"hello":"world"}', config);

    expect(lastHeaders['x-agent-id']).toBe('test-agent-123');
    expect(lastHeaders['x-timestamp']).toBeTruthy();
    expect(lastHeaders['x-signature']).toBeTruthy();
  });

  it('should produce a valid signature', async () => {
    responseStatus = 200;
    responseBody = JSON.stringify({ ok: true });

    const body = JSON.stringify({ data: 'test' });
    await signedFetch('POST', '/api/verify', body, config);

    const timestamp = lastHeaders['x-timestamp'] as string;
    const sigB64 = lastHeaders['x-signature'] as string;
    const sig = fromBase64Url(sigB64);
    const bodyBytes = new TextEncoder().encode(body);

    const valid = signatures.verifyRequest(
      keys.publicKey,
      timestamp,
      'POST',
      '/api/verify',
      bodyBytes,
      sig,
    );
    expect(valid).toBe(true);
  });

  it('should throw AuthError for 401', async () => {
    responseStatus = 401;
    responseBody = JSON.stringify({ error: 'unauthorized' });

    await expect(signedFetch('GET', '/api/fail', null, config)).rejects.toThrow(AuthError);
  });

  it('should throw NotFoundError for 404', async () => {
    responseStatus = 404;
    responseBody = JSON.stringify({ error: 'not found' });

    await expect(signedFetch('GET', '/api/missing', null, config)).rejects.toThrow(NotFoundError);
  });

  it('should throw ConflictError for 409', async () => {
    responseStatus = 409;
    responseBody = JSON.stringify({ error: 'conflict' });

    await expect(signedFetch('GET', '/api/dup', null, config)).rejects.toThrow(ConflictError);
  });

  it('should throw ServerError for 500', async () => {
    responseStatus = 500;
    responseBody = JSON.stringify({ error: 'internal' });

    await expect(signedFetch('GET', '/api/broken', null, config)).rejects.toThrow(ServerError);
  });
});
