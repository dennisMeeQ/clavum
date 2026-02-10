# 002 — Pairing: Plan

## Approach

Implement pairing across all three components: server API (Hono), CLI (`clavum pair`), and PWA (QR scan). Server is the hub — both agent and phone pair with it.

## Server Changes (`packages/server/`)

### Database (Prisma schema already exists)
- Tenant model: id, name, server keypair
- Agent model: id, tenant_id, name, x25519_pub, ed25519_pub, allowed_ips, machine_fingerprint
- Phone model: id, tenant_id, name, x25519_pub, ed25519_pub, push_endpoint
- PairingInvitation model (new): id, tenant_id, token (random 32 bytes, base64url), type (agent|phone), expires_at, used (boolean)

### API Routes (`src/routes/pair.ts`, new)
- `POST /api/tenants` — create tenant, generate server X25519 keypair, store in DB
- `POST /api/pair/invite` — create invitation: generate token, store with 10-min expiry, return `{ token, qr: { pub, token, url } }`
- `POST /api/pair/agent` — validate token → register agent (x25519_pub + ed25519_pub) → invalidate token → return `{ server_x25519_pub, fingerprint_bytes }`
- `POST /api/pair/phone` — same flow for phone
- `GET /api/pair/verify/:token` — return fingerprint data for the pairing associated with this token

### Server Keypair Management
- On tenant creation: `x25519.generateKeypair()` → store both keys in Tenant row
- Server private key loaded from DB per-tenant when needed for ECDH

### Fingerprint Derivation
- After registering agent/phone, derive: `HKDF(X25519(server_priv, agent/phone_pub), "clavum-fingerprint", "verify", 4)`
- Map 4 bytes to 4 emoji from a fixed set of 256 emoji
- Return emoji fingerprint to both sides for visual comparison

## CLI Changes (`packages/cli/`)

### `clavum pair <server-url>` command
1. Check if already paired → warn + confirm overwrite
2. Generate X25519 + Ed25519 keypairs via `@clavum/crypto`
3. Store private keys:
   - Try OS Keychain first (use `keytar` or Node `keychain` module)
   - Fallback: write to `~/.clavum/agent_x25519.key` + `~/.clavum/agent_ed25519.key` with chmod 600
   - Warn on file fallback
4. Prompt user for pairing token (or accept `--token` flag)
5. POST to `/api/pair/agent` with public keys + token
6. Receive server public key + fingerprint
7. Display emoji fingerprint in terminal
8. Store server URL + server public key in config file (`~/.clavum/config.json`)
9. Initialize SQLite vault (`~/.clavum/vault.db`) with secret table schema

### Vault Schema (SQLite)
```sql
CREATE TABLE secrets (
  secret_id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  tier TEXT NOT NULL CHECK(tier IN ('green', 'yellow', 'red')),
  encrypted_blob BLOB NOT NULL,
  blob_iv BLOB NOT NULL,
  blob_tag BLOB NOT NULL,
  encrypted_dek BLOB NOT NULL,
  dek_iv BLOB NOT NULL,
  dek_tag BLOB NOT NULL,
  kek_salt BLOB NOT NULL,
  eph_x25519_pub BLOB,
  aad BLOB NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
```

### Key Storage Abstraction (`src/keystore.ts`, new)
- `keystore.store(name, key)` — try Keychain, fallback to file
- `keystore.load(name)` → Uint8Array
- `keystore.exists(name)` → boolean
- Platform detection for Keychain availability

## PWA Changes (`packages/pwa/`)

### Pairing Screen
- QR code scanner (camera access via `getUserMedia`)
- Parse QR JSON payload: extract server_pub, token, url
- Generate X25519 + Ed25519 keypairs via WebCrypto
- POST to `/api/pair/phone` with public keys + token
- Display emoji fingerprint for human verification
- Store keys in IndexedDB, server pub in localStorage

### Key Storage
- X25519 + Ed25519 private keys in IndexedDB
- Server public key + URL in localStorage
- Pairing state: unpaired → pairing → paired

## Emoji Fingerprint Set

Define a fixed array of 256 emoji (deterministic, no platform-dependent rendering). Map each byte of the 4-byte fingerprint to one emoji. Display as 4 emoji in sequence.

## Test Plan

### Server Tests
- `tests/unit/pair.test.ts`: token generation, expiry, single-use validation
- `tests/integration/pair.test.ts`: full pairing flow against test DB
  - Create tenant → create invitation → agent pairs → phone pairs
  - Expired token rejected
  - Reused token rejected
  - Invalid token format rejected
  - Fingerprints match between server and client calculation

### CLI Tests
- `tests/unit/keystore.test.ts`: store/load/exists with file fallback
- `tests/integration/pair.test.ts`: full `clavum pair` flow with mocked HTTP
  - Keypair generated and stored
  - Server public key saved
  - Vault SQLite initialized
  - Fingerprint displayed
  - Already-paired warning

### PWA Tests
- `tests/unit/crypto.test.ts`: WebCrypto keygen + ECDH
- `tests/e2e/pairing.test.ts` (Playwright): scan QR → pair → show fingerprint

## Dependencies

### Server
- None new (Hono + Prisma already in place)

### CLI
- `better-sqlite3` (already in package.json)
- Keychain access TBD: `keytar` or native Node APIs

### PWA
- QR scanner library (e.g. `html5-qrcode` or `jsQR`)
