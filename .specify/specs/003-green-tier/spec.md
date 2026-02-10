# 003 — Green Tier (Store + Retrieve)

## Summary

Implement the first complete end-to-end secret flow: storing and retrieving green-tier secrets. Green tier uses 2-party ECDH (agent + server) with automatic approval — no human involvement. This is the foundation that yellow and red tiers build upon.

## Requirements

### Storing a Secret

- Agent encrypts a secret locally and stores it in the SQLite vault
- Flow:
  1. Generate random DEK (32 bytes)
  2. Generate random blob_iv (12 bytes)
  3. Construct AAD: `secret_id ‖ "green" ‖ agent_id`
  4. Encrypt secret: `AES-256-GCM(DEK, plaintext, blob_iv, aad)` → encrypted_blob + blob_tag
  5. Generate ephemeral X25519 keypair (`eph_x25519_priv`, `eph_x25519_pub`)
  6. Derive `K_eph = X25519(eph_x25519_priv, server_x25519_pub)`
  7. Generate random kek_salt (32 bytes)
  8. Derive `KEK = HKDF(K_eph, kek_salt, "clavum-kek-v1" ‖ secret_id, 32)`
  9. Generate random dek_iv (12 bytes)
  10. Wrap DEK: `AES-256-GCM(KEK, DEK, dek_iv, aad)` → encrypted_dek + dek_tag
  11. Store vault record: all encrypted material + eph_x25519_pub + kek_salt + metadata
  12. Wipe: DEK, KEK, K_eph, eph_x25519_priv, plaintext
- After storage, register secret metadata with server: `{ secret_id, name, tier: "green" }`

### Retrieving a Secret

- Agent requests KEK from server, then decrypts locally
- Flow:
  1. Check in-memory DEK cache → if hit, skip to step 12
  2. Sign request: `Ed25519_sign(agent_ed25519_priv, timestamp ‖ ":" ‖ method ‖ ":" ‖ path ‖ ":" ‖ SHA256(body))`
  3. Send to server: `GET /api/secrets/{secret_id}` with eph_x25519_pub, kek_salt, reason, timestamp, signature
  4. Server verifies Ed25519 signature + timestamp freshness (60s window) + nonce dedup
  5. Server checks tier → green → auto-approve
  6. Server derives: `K_eph = X25519(server_x25519_priv, eph_x25519_pub)`
  7. Server derives: `KEK = HKDF(K_eph, kek_salt, "clavum-kek-v1" ‖ secret_id, 32)`
  8. Server derives: `K_session = X25519(server_x25519_priv, agent_x25519_pub)`
  9. Server encrypts: `enc_kek = AES-256-GCM(K_session, KEK)` → sends to agent
  10. Server wipes K_eph, KEK. Writes audit log.
  11. Agent derives: `K_session = X25519(agent_x25519_priv, server_x25519_pub)`
  12. Agent decrypts: `KEK = AES-256-GCM-decrypt(K_session, enc_kek)`
  13. Agent unwraps: `DEK = AES-256-GCM-decrypt(KEK, encrypted_dek, dek_iv, aad, dek_tag)`
  14. Agent decrypts: `plaintext = AES-256-GCM-decrypt(DEK, encrypted_blob, blob_iv, aad, blob_tag)`
  15. Cache DEK in memory with TTL (default: 4 hours)
  16. Wipe KEK, K_session. Plaintext wiped after use by caller.

### DEK Caching

- Green tier caches DEK in agent memory after first retrieval
- Cache is keyed by secret_id with configurable TTL (default 4 hours)
- Cached DEK allows offline retrieval (no server round-trip)
- Cache is in-memory only — lost on process restart
- On TTL expiry, DEK is wiped from cache; next access requires server

### CLI Commands

- `clavum store <name> --tier green` — reads secret value from stdin, stores in vault
- `clavum get <name> --reason "..."` — retrieves and prints to stdout
- `clavum list` — lists all secrets (name, tier, created_at)
- `clavum delete <name>` — removes from vault + deregisters from server
- All commands support `--json` flag for structured output
- Exit codes: 0 success, 1 error, 2 timeout

### Server API Endpoints

- `POST /api/secrets/register` — register secret metadata (agent sends after storing)
- `POST /api/secrets/:id/retrieve` — green retrieval flow (verify signature → derive KEK → return enc_kek)
- `DELETE /api/secrets/:id` — deregister secret metadata
- `GET /api/secrets` — list secret metadata for an agent
- All endpoints require Ed25519 signed requests

### Audit Logging

- Server logs every retrieval: agent_id, secret_id, reason, tier, result (auto_granted), timestamp, latency
- Audit log stored in Postgres
- `GET /api/audit` — query audit log (filterable by secret, agent, date range)

### Request Authentication

- Every agent→server request includes: timestamp, Ed25519 signature, agent_id
- Server verifies signature against registered agent public key
- Server rejects if timestamp > 60 seconds old
- Server rejects replayed requests (nonce dedup: store seen signatures, expire after 60s)

### Error Handling

- Secret not found → exit 1 + clear error message
- Server unreachable + DEK cached → return cached secret (green only)
- Server unreachable + no cache → exit 1 + "server unreachable, no cached DEK"
- Invalid signature → HTTP 401
- Unknown agent → HTTP 403
- Nonce replay → HTTP 409

## Non-Requirements

- No yellow or red tier flows (separate specs)
- No phone involvement
- No push notifications
- No secret rotation (update = delete + re-store for now)
- No import/export

## Acceptance Criteria

- Full round-trip: `clavum store` → `clavum get` returns original secret
- Server cannot decrypt the secret (only derives KEK, never sees plaintext)
- Compromising only the agent machine OR only the server cannot recover secrets
- DEK caching works: second `clavum get` within TTL doesn't contact server
- DEK cache expires: after TTL, next `clavum get` contacts server again
- Offline retrieval works with cached DEK
- All request signatures verified; invalid/expired/replayed requests rejected
- Audit log records every retrieval with reason
- `--json` output is valid JSON with consistent structure
- CLI exit codes are correct for all scenarios
- Biome + typecheck + all tests pass
- Server integration tests against real Postgres
- CLI tests against real SQLite + mocked server
