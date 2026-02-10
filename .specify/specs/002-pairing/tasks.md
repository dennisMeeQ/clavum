# 002 — Pairing: Tasks

**Depends on:** 001 (crypto core must be complete)

## Task 1: Prisma schema update + migrations ✅
- Add PairingInvitation model to `prisma/schema.prisma`:
  - id, tenant_id, token (unique), type (agent|phone), expires_at, used, created_at
- Run `prisma migrate dev` to create migration
- **Tests:** Schema compiles, migration applies cleanly

## Task 2: Tenant management API ✅
**Files:** `packages/server/src/routes/tenants.ts` (new)
- `POST /api/tenants` — create tenant with name, generate server X25519 keypair, store in DB
- `GET /api/tenants/:id` — return tenant info (public key, not private)
- **Tests:** `tests/integration/tenants.test.ts`
  - Create tenant → keypair stored in DB
  - Get tenant → returns public key
  - Public key is valid 32-byte X25519 key

## Task 3: Pairing invitation API ✅
**Files:** `packages/server/src/routes/pair.ts` (new)
- `POST /api/pair/invite` — create invitation: random token, 10-min expiry, return QR JSON payload
- Token: `crypto.randomBytes(32).toString('base64url')`
- QR payload: `{ pub: base64url(server_x25519_pub), token, url: serverUrl }`
- **Tests:** `tests/integration/pair-invite.test.ts`
  - Invitation created with 10-min expiry
  - Token is unique
  - QR payload contains valid pub + token + url

## Task 4: Agent pairing API ✅
**Files:** `packages/server/src/routes/pair.ts` (continued)
- `POST /api/pair/agent` — body: `{ token, x25519_pub, ed25519_pub, name }`
  - Validate token (exists, not expired, not used, type matches)
  - Register agent in DB
  - Invalidate token
  - Derive fingerprint: `kdf.deriveFingerprint(x25519.sharedSecret(server_priv, agent_pub))`
  - Return `{ server_x25519_pub, fingerprint }`
- **Tests:** `tests/integration/pair-agent.test.ts`
  - Valid token → agent registered, token invalidated
  - Expired token → 400
  - Already-used token → 400
  - Invalid token → 404
  - Missing fields → 400
  - Fingerprint matches local calculation

## Task 5: Phone pairing API ✅
**Files:** `packages/server/src/routes/pair.ts` (continued)
- `POST /api/pair/phone` — same flow as agent but registers Phone model
- **Tests:** `tests/integration/pair-phone.test.ts`
  - Same test cases as agent pairing
  - Phone registered with correct public keys

## Task 6: Emoji fingerprint mapping ✅
**Files:** `packages/crypto/src/emoji.ts` (new)
- Define array of 256 emoji (curated set, consistent cross-platform rendering)
- `fingerprintToEmoji(bytes: Uint8Array)` → string (4 emoji)
- Export from `@clavum/crypto`
- **Tests:** `tests/unit/emoji.test.ts`
  - Maps 4 bytes to 4 emoji
  - Deterministic (same input → same emoji)
  - All 256 entries are unique

## Task 7: CLI keystore ✅
**Files:** `packages/cli/src/keystore.ts` (new)
- `store(name, key)` — try OS Keychain, fallback to file
- `load(name)` → Uint8Array or null
- `exists(name)` → boolean
- File fallback: write to `~/.clavum/<name>.key` with chmod 600
- Log warning on file fallback
- Platform detection: check if keytar/Keychain is available
- **Tests:** `tests/unit/keystore.test.ts`
  - Store and load round-trip (file fallback)
  - File has correct permissions (600)
  - Exists returns true/false correctly
  - Note: Keychain tests may need mocking

## Task 8: CLI vault initialization ✅
**Files:** `packages/cli/src/vault.ts` (new)
- `initVault(dbPath)` — create SQLite DB + tables (secrets + config)
- `getConfig(key)` / `setConfig(key, value)` — read/write config table
- Schema from plan (secrets table + config table)
- **Tests:** `tests/unit/vault.test.ts`
  - Init creates DB file
  - Tables created with correct schema
  - Config get/set round-trip
  - Init is idempotent (running twice doesn't error)

## Task 9: CLI `clavum pair` command
**Files:** `packages/cli/src/commands/pair.ts` (new), update `src/index.ts`
- Parse `clavum pair <server-url> --token <token>`
- Generate X25519 + Ed25519 keypairs
- Store via keystore
- POST to `/api/pair/agent`
- Display emoji fingerprint
- Save server URL + server pub in vault config
- Initialize vault if not exists
- **Tests:** `tests/integration/pair.test.ts`
  - Full pair flow (mocked HTTP)
  - Already paired → warn + confirm
  - Server error → clean error message
  - Fingerprint displayed correctly

## Task 10: PWA pairing screen (basic)
**Files:** `packages/pwa/src/routes/pair/+page.svelte` (new)
- QR scanner (use `html5-qrcode` or similar)
- Parse QR JSON
- Generate keypairs via WebCrypto
- POST to `/api/pair/phone`
- Display emoji fingerprint
- Store keys in IndexedDB
- **Tests:** `tests/e2e/pairing.test.ts` (Playwright)
  - Note: E2E tests are stretch goal; unit test WebCrypto operations first

## Order

```
[1] Prisma schema ───────────────────────┐
[2] Tenant API ──────────────────────────┤
[3] Invitation API ──────────────────────┼──→ [4] Agent pair API ──→ [9] CLI pair
[6] Emoji mapping ───────────────────────┤    [5] Phone pair API ──→ [10] PWA pair
[7] CLI keystore ────────────────────────┤
[8] CLI vault init ──────────────────────┘
```

Tasks 1, 6, 7, 8 are independent.
Tasks 2-5 are sequential (2 → 3 → 4/5 parallel).
Task 9 depends on 3, 4, 6, 7, 8.
Task 10 depends on 3, 5, 6.
