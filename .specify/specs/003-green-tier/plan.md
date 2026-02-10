# 003 — Green Tier: Plan

## Approach

Implement the full store + retrieve cycle for green-tier secrets. This touches all three layers: CLI (user-facing), server (KEK derivation + auth), and crypto (already done in 001). The PWA is not involved in green tier.

## Server Changes (`packages/server/`)

### API Routes (`src/routes/secrets.ts`, new)

#### `POST /api/secrets/register`
- Auth: Ed25519 signed request
- Body: `{ secret_id, name, tier }`
- Creates SecretMetadata row in Postgres
- Returns 201

#### `POST /api/secrets/:id/retrieve`
- Auth: Ed25519 signed request
- Body: `{ eph_x25519_pub, kek_salt, reason }`
- Flow:
  1. Verify request signature (call `signatures.verifyRequest`)
  2. Check nonce dedup (reject if signature seen in last 60s)
  3. Look up secret metadata → confirm tier is green
  4. Derive `K_eph = X25519(server_x25519_priv, eph_x25519_pub)`
  5. Derive `KEK = HKDF(K_eph, kek_salt, "clavum-kek-v1" ‖ secret_id, 32)`
  6. Derive `K_session = X25519(server_x25519_priv, agent_x25519_pub)`
  7. Encrypt: `enc_kek = AES_GCM(K_session, KEK)`
  8. Wipe K_eph, KEK
  9. Write audit log
  10. Return `{ enc_kek, enc_kek_iv, enc_kek_tag }`
- Returns 200

#### `DELETE /api/secrets/:id`
- Auth: Ed25519 signed request
- Deletes SecretMetadata row
- Returns 204

#### `GET /api/secrets`
- Auth: Ed25519 signed request
- Returns list of `{ secret_id, name, tier, created_at }` for the authenticated agent

#### `GET /api/audit`
- Auth: Ed25519 signed request
- Query params: secret_id?, from?, to?, limit?
- Returns audit log entries

### Request Authentication Middleware (`src/middleware/auth.ts`, new)
- Extract agent_id, timestamp, signature from request headers
- Load agent's ed25519_pub from DB
- Call `signatures.verifyRequest(pub, timestamp, method, path, body, sig)`
- Check nonce dedup (store in UsedNonce table, clean up expired)
- Set `c.set('agent', agent)` on Hono context
- Return 401 on invalid signature, 409 on replay

### Nonce Dedup
- On each request: store `SHA256(signature)` in UsedNonce table with 60s expiry
- Before verifying: check if nonce exists → 409 Conflict
- Background cleanup: delete expired nonces (cron or on-request lazy cleanup)

### Audit Logging (`src/services/audit.ts`, new)
- `createAuditEntry({ agentId, secretId, reason, tier, result, latencyMs })`
- Writes to AuditLog table in Postgres

## CLI Changes (`packages/cli/`)

### `clavum store <name> --tier green`
1. Read secret from stdin (or `--value` flag for non-interactive)
2. Generate secret_id (UUID v4)
3. Load agent keypairs + server public key from keystore/config
4. Run green storage flow (from `@clavum/crypto` flows):
   - Generate DEK, encrypt plaintext, generate ephemeral keypair, derive KEK, wrap DEK
5. Insert vault record into SQLite
6. POST `/api/secrets/register` with secret_id, name, tier
7. Print success (or `--json` with secret_id)

### `clavum get <name> --reason "..."`
1. Look up secret in SQLite vault by name
2. Check DEK cache → if hit, decrypt directly, skip server
3. Load agent keypairs + server public key
4. Read eph_x25519_pub + kek_salt from vault record
5. POST `/api/secrets/:id/retrieve` with signed request
6. Receive enc_kek → decrypt with K_session → get KEK
7. Unwrap DEK with KEK
8. Decrypt plaintext with DEK
9. Cache DEK with TTL (in-memory process cache)
10. Print plaintext to stdout (or `--json` with metadata)
11. Wipe KEK, K_session

### `clavum list`
- Query SQLite vault: `SELECT name, tier, created_at FROM secrets ORDER BY name`
- Display as table (or `--json`)

### `clavum delete <name>`
- Delete from SQLite vault
- DELETE `/api/secrets/:id` on server
- Confirm before deleting (or `--force` flag)

### DEK Cache (`src/cache.ts`, new)
- In-memory Map: `secret_id → { dek, expiresAt }`
- `cache.get(secretId)` → DEK or null (auto-expires)
- `cache.set(secretId, dek, ttlMs)` — default 4 hours
- `cache.clear()` — wipe all
- Note: cache only lives during CLI process lifetime. For long-running agents, this matters. For one-shot CLI calls, cache is empty each time.

**Important consideration:** The CLI is invoked per-command (not a long-running daemon). This means the DEK cache is only useful if the CLI becomes a daemon or is used as a library. For now, implement the cache but document that it's only effective in library/daemon mode. Each `clavum get` invocation will hit the server.

### HTTP Client (`src/http.ts`, new)
- `signedRequest(method, path, body, agentPrivKey)` → fetch with auth headers
- Sets headers: `X-Agent-Id`, `X-Timestamp`, `X-Signature`
- Parses response, handles errors (401, 403, 409, 5xx)

## Test Plan

### Server Tests

#### Unit
- `tests/unit/auth-middleware.test.ts`:
  - Valid signature → passes
  - Invalid signature → 401
  - Expired timestamp → 401
  - Replayed nonce → 409
  - Missing headers → 401

#### Integration
- `tests/integration/secrets.test.ts`:
  - Register secret metadata
  - Retrieve green secret: full KEK derivation flow
  - Agent A cannot retrieve Agent B's secret
  - Delete secret
  - List secrets (scoped to agent)
  - Audit log written on retrieval
  - Audit log queryable

### CLI Tests

#### Unit
- `tests/unit/cache.test.ts`: set/get/expire/clear
- `tests/unit/http.test.ts`: request signing, header construction

#### Integration
- `tests/integration/store-get.test.ts`:
  - Store → get round-trip (mocked server)
  - Store with `--json` output
  - Get with `--json` output
  - Get with cached DEK (no server call)
  - Get without cache (server called)
  - Get server unreachable + no cache → error
  - List secrets
  - Delete secret
  - Reason required for get (missing → error)

### End-to-End (stretch)
- Full stack test: real server + real CLI + real SQLite + real Postgres
- Store via CLI → retrieve via CLI → verify plaintext matches

## File Structure After Implementation

```
packages/server/src/
├── app.ts              (updated: mount new routes)
├── index.ts
├── routes/
│   ├── pair.ts         (from 002)
│   └── secrets.ts      (new)
├── middleware/
│   └── auth.ts         (new)
└── services/
    └── audit.ts        (new)

packages/cli/src/
├── index.ts            (updated: command routing)
├── commands/
│   ├── pair.ts         (from 002)
│   ├── store.ts        (new)
│   ├── get.ts          (new)
│   ├── list.ts         (new)
│   └── delete.ts       (new)
├── vault.ts            (new: SQLite operations)
├── cache.ts            (new: DEK cache)
├── http.ts             (new: signed HTTP client)
└── keystore.ts         (from 002)
```

## Dependencies

### Server
- None new

### CLI
- `uuid` (for generating secret_id) — or use `crypto.randomUUID()`
