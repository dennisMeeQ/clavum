/**
 * Signed HTTP client for Clavum CLI.
 *
 * Wraps fetch with Ed25519 request signatures for server auth.
 * Sets X-Agent-Id, X-Timestamp, X-Signature headers.
 */

import { signatures, toBase64Url } from '@clavum/crypto';

export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConflictError';
  }
}

export class ServerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ServerError';
  }
}

export interface SignedFetchConfig {
  agentId: string;
  ed25519Priv: Uint8Array;
  serverUrl: string;
}

/**
 * Make an authenticated HTTP request to the Clavum server.
 *
 * Signs the request with the agent's Ed25519 private key and
 * sets the required auth headers.
 */
export async function signedFetch(
  method: string,
  path: string,
  body: string | null,
  config: SignedFetchConfig,
): Promise<unknown> {
  const timestamp = Date.now().toString();
  const bodyBytes = new TextEncoder().encode(body ?? '');
  const sig = signatures.signRequest(config.ed25519Priv, timestamp, method, path, bodyBytes);

  const headers: Record<string, string> = {
    'X-Agent-Id': config.agentId,
    'X-Timestamp': timestamp,
    'X-Signature': toBase64Url(sig),
  };

  if (body !== null) {
    headers['Content-Type'] = 'application/json';
  }

  const url = `${config.serverUrl}${path}`;
  const res = await fetch(url, {
    method,
    headers,
    body: body ?? undefined,
  });

  if (res.status === 204) {
    return null;
  }

  const json = await res.json().catch(() => ({}));

  if (res.status === 401) {
    throw new AuthError((json as { error?: string }).error ?? 'authentication failed');
  }
  if (res.status === 403) {
    throw new AuthError((json as { error?: string }).error ?? 'forbidden');
  }
  if (res.status === 404) {
    throw new NotFoundError((json as { error?: string }).error ?? 'not found');
  }
  if (res.status === 409) {
    throw new ConflictError((json as { error?: string }).error ?? 'conflict');
  }
  if (res.status >= 500) {
    throw new ServerError((json as { error?: string }).error ?? 'server error');
  }
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}: ${JSON.stringify(json)}`);
  }

  return json;
}
