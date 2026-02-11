# 003 — Green Tier: Tasks

**Depends on:** 001 (crypto core), 002 (pairing — agent must be paired with server)

## Task 1: Request auth middleware ✅
**Files:** `packages/server/src/middleware/auth.ts` (new)
- Extract `X-Agent-Id`, `X-Timestamp`, `X-Signature` from request headers
- Load agent's `ed25519_pub` from DB by agent_id
- Call `signatures.verifyRequest(pub, timestamp, method, path, body, sig)`
- Nonce dedup: hash signature, check UsedNonce table, insert if new
- Set `c.set('agent', agent)` on Hono context for downstream handlers
- Return 401: invalid signature, expired timestamp, unknown agent
- Return 409: replayed nonce
- **Tests:** `tests/unit/auth-middleware.test.ts`
  - Valid signature → passes, agent set on context
  - Invalid signature → 401
  - Expired timestamp (>60s) → 401
  - Missing headers → 401
  - Unknown agent_id → 401 (not 404, avoid enumeration)
  - Replayed nonce → 409

## Task 2: Nonce cleanup ✅
**Files:** `packages/server/src/services/nonce.ts` (new)
- `storeNonce(signatureHash, expiresAt)` — insert into UsedNonce table
- `isReplay(signatureHash)` → boolean
- `cleanExpired()` — delete nonces older than 60s
- Lazy cleanup: run on every Nth request, or on a timer
- **Tests:** `tests/unit/nonce.test.ts`
  - Store + check → is replay
  - Check unknown → not replay
  - Expired nonce → cleaned up, no longer detected as replay

## Task 3: Audit logging service ✅
**Files:** `packages/server/src/services/audit.ts` (new)
- `createEntry({ agentId, secretId, reason, tier, result, latencyMs, proof? })`
- Writes to AuditLog table
- `queryEntries({ agentId?, secretId?, from?, to?, limit? })` → entries
- **Tests:** `tests/unit/audit.test.ts`
  - Create entry → stored in DB
  - Query by agent, secret, date range
  - Limit works

## Task 4: Secret metadata API ✅
**Files:** `packages/server/src/routes/secrets.ts` (new)
- `POST /api/secrets/register` — register metadata (secret_id, name, tier). Auth required.
- `GET /api/secrets` — list secrets for authenticated agent. Auth required.
- `DELETE /api/secrets/:id` — deregister. Auth required. Only owning agent can delete.
- **Tests:** `tests/integration/secrets-metadata.test.ts`
  - Register → listed in GET
  - Agent A can't see Agent B's secrets
  - Agent A can't delete Agent B's secrets
  - Duplicate name for same agent → 409

## Task 5: Green retrieval API endpoint ✅
**Files:** `packages/server/src/routes/secrets.ts` (continued)
- `POST /api/secrets/:id/retrieve` — the core green flow on server side
  - Auth middleware → verified agent
  - Body: `{ eph_x25519_pub, kek_salt, reason }` (base64url encoded bytes)
  - Validate: secret exists, belongs to agent, tier is green
  - Load server_x25519_priv for the agent's tenant
  - Derive K_eph, KEK, K_session (using `@clavum/crypto`)
  - Encrypt KEK for transport: `enc_kek = AES_GCM(K_session, KEK)`
  - Wipe K_eph, KEK
  - Write audit log (result: auto_granted)
  - Return `{ enc_kek, enc_kek_iv, enc_kek_tag }` (base64url)
- **Tests:** `tests/integration/secrets-retrieve.test.ts`
  - Full green retrieval flow → returns enc_kek
  - Agent can decrypt enc_kek with own K_session → gets correct KEK
  - KEK unwraps DEK → decrypts original secret (end-to-end crypto verification)
  - Wrong agent → 403
  - Non-existent secret → 404
  - Missing reason → 400
  - Audit log written with correct fields

## Task 6: Audit query API ✅
**Files:** `packages/server/src/routes/audit.ts` (new)
- `GET /api/audit` — query params: secret_id, from, to, limit (default 50)
- Auth required. Returns audit entries for authenticated agent's secrets only.
- **Tests:** `tests/integration/audit.test.ts`
  - Returns entries after retrieval
  - Filterable by secret_id
  - Filterable by date range
  - Agent A can't see Agent B's audit entries

## Task 7: CLI signed HTTP client
**Files:** `packages/cli/src/http.ts` (new)
- `signedFetch(method, path, body, config)` — wraps fetch with auth headers
  - Loads agent_ed25519_priv from keystore
  - Sets X-Agent-Id, X-Timestamp, X-Signature headers
  - Handles response: parse JSON, throw on error status
- Error classes: `AuthError`, `NotFoundError`, `ConflictError`, `ServerError`
- **Tests:** `tests/unit/http.test.ts`
  - Correct headers set
  - Signature is valid (verify with public key)
  - Error classes thrown for 401, 404, 409, 500

## Task 8: CLI vault CRUD operations
**Files:** `packages/cli/src/vault.ts` (extend from 002)
- `insertSecret(record)` — insert vault record into SQLite
- `getSecret(name)` → vault record or null
- `listSecrets()` → array of `{ name, tier, created_at }`
- `deleteSecret(name)` → boolean
- `getSecretById(id)` → vault record or null
- **Tests:** `tests/unit/vault-crud.test.ts`
  - Insert → get round-trip
  - List returns all secrets
  - Delete removes secret
  - Get nonexistent → null
  - Duplicate name → error

## Task 9: CLI `clavum store` command
**Files:** `packages/cli/src/commands/store.ts` (new), update `src/index.ts`
- Parse: `clavum store <name> --tier green [--value <val>]`
- Read secret from stdin (or --value)
- Generate secret_id via `crypto.randomUUID()`
- Run green storage flow using `@clavum/crypto` flows
- Insert vault record via vault.ts
- POST `/api/secrets/register` via http.ts
- Output: success message (or `--json` with secret_id)
- **Tests:** `tests/integration/store.test.ts`
  - Store → record in SQLite
  - Metadata registered on server (mocked)
  - `--json` output parseable
  - Missing name → error
  - Missing tier → error

## Task 10: CLI DEK cache
**Files:** `packages/cli/src/cache.ts` (new)
- In-memory Map: `secret_id → { dek: Uint8Array, expiresAt: number }`
- `get(secretId)` → DEK or null (checks expiry, wipes if expired)
- `set(secretId, dek, ttlMs)` — default 4 hours
- `clear()` — wipe all DEKs
- Note in docs: only effective in library/daemon mode, not one-shot CLI
- **Tests:** `tests/unit/cache.test.ts`
  - Set → get returns DEK
  - Expired → get returns null
  - Clear wipes all
  - Different secrets cached independently

## Task 11: CLI `clavum get` command
**Files:** `packages/cli/src/commands/get.ts` (new), update `src/index.ts`
- Parse: `clavum get <name> --reason "..."`
- Look up in vault by name
- Check DEK cache → hit: decrypt directly
- Cache miss: POST `/api/secrets/:id/retrieve` → decrypt enc_kek → unwrap DEK → decrypt secret
- Cache DEK (green tier only)
- Print plaintext to stdout (or `--json`)
- Wipe KEK, K_session after use
- Exit 1 on error, exit 0 on success
- **Tests:** `tests/integration/get.test.ts`
  - Store → get round-trip (mocked server)
  - Cached DEK → no server call
  - Missing reason → error
  - Secret not found → error + exit 1
  - Server unreachable + no cache → error
  - `--json` output includes metadata

## Task 12: CLI `clavum list` and `clavum delete`
**Files:** `packages/cli/src/commands/list.ts`, `packages/cli/src/commands/delete.ts` (new)
- List: query vault, display table or `--json`
- Delete: confirm (or `--force`), delete from vault + server
- **Tests:** `tests/integration/list-delete.test.ts`
  - List shows stored secrets
  - List empty vault → empty output
  - Delete → removed from vault + server (mocked)
  - Delete nonexistent → error

## Task 13: Mount routes and final integration
**Files:** `packages/server/src/app.ts` (update)
- Mount auth middleware on `/api/*` (except pairing routes)
- Mount secrets routes
- Mount audit routes
- **Tests:** `tests/integration/full-flow.test.ts`
  - End-to-end: create tenant → pair agent → store secret → retrieve secret → verify plaintext
  - This is the "golden path" integration test

## Order

```
[1] Auth middleware ──────────────┐
[2] Nonce cleanup ───────────────┤
[3] Audit service ───────────────┼──→ [5] Retrieve API ──→ [13] Full integration
[4] Metadata API ────────────────┘    [6] Audit API
[7] CLI HTTP client ─────────────┐
[8] CLI vault CRUD ──────────────┼──→ [9] CLI store ──→ [11] CLI get ──→ [13]
[10] DEK cache ──────────────────┘    [12] CLI list/delete
```

Tasks 1-4 (server) and 7-8, 10 (CLI) can run in parallel.
Task 5 depends on 1-4.
Task 11 depends on 5, 7-10.
Task 13 depends on everything.
