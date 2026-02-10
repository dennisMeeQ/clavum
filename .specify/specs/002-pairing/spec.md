# 002 — Pairing

## Summary

Implement the trust establishment ceremony between Clavum's three components: agent machine ↔ server, and phone ↔ server. After pairing, each party knows the others' public keys and can perform ECDH. This is the prerequisite for all secret operations.

## Requirements

### Server-Side Pairing Management

- Server generates a per-tenant X25519 keypair at tenant creation
- Server can create pairing invitations (one-time tokens, 10-minute expiry)
- Server stores registered agents and phones with their public keys
- Server exposes its public key via pairing invitation

### Agent Pairing (`clavum pair`)

- Agent generates two keypairs locally: X25519 (ECDH) + Ed25519 (signing)
- Agent stores private keys in OS Keychain (macOS Keychain, Linux secret-service); falls back to `~/.clavum/agent_x25519.key` and `~/.clavum/agent_ed25519.key` with `chmod 600`
- CLI warns if falling back to file storage
- Agent sends its public keys to the server using the one-time pairing token
- Server registers the agent and returns the server's public key
- Both sides display a 4-emoji fingerprint derived from shared key material: `HKDF(X25519(agent_priv, server_pub), "clavum-fingerprint", "verify", 4)` → mapped to emoji
- Human visually confirms emoji match on CLI output and phone/server UI
- Agent stores server public key locally
- Pairing token is invalidated after use

### Phone Pairing (PWA)

- Server displays a QR code containing JSON: `{"pub": "<base64url server_x25519_pub>", "token": "<pairing_token>", "url": "<server_url>"}`
- Phone scans QR code via PWA
- Phone generates two keypairs: X25519 (ECDH) + Ed25519 (signing) via WebCrypto
- Phone sends its public keys to the server using the pairing token
- Server registers the phone
- Both sides display the 4-emoji fingerprint for human verification
- Phone stores server public key in IndexedDB

### Pairing Security

- Pairing tokens are cryptographically random, single-use, expire in 10 minutes
- Expired or already-used tokens are rejected
- Fingerprint verification detects MITM during key exchange
- Each agent/phone pairing is unique — re-pairing generates new keypairs

### CLI Vault Initialization

- On first `clavum pair`, create `~/.clavum/` directory if it doesn't exist
- Create SQLite vault database (`~/.clavum/vault.db`) with the schema for encrypted secrets
- Store server URL and server public key in vault metadata

### API Endpoints

- `POST /api/tenants` — create a tenant (generates server keypair)
- `POST /api/pair/invite` — create a pairing invitation (returns token + QR payload)
- `POST /api/pair/agent` — agent submits public keys with token → registered
- `POST /api/pair/phone` — phone submits public keys with token → registered
- `GET /api/pair/verify/:token` — return fingerprint data for verification

### Multi-Tenant

- Each tenant has its own server keypair
- Agents and phones are scoped to a tenant
- Pairing tokens are scoped to a tenant

## Non-Requirements

- No secret storage/retrieval yet (that's 003)
- No approval flows yet (that's yellow/red tier)
- No push notification setup yet (can be added later)
- No agent-to-agent or phone-to-phone communication

## Acceptance Criteria

- Agent can pair with server via CLI: `clavum pair <server-url>`
- Phone can pair with server via QR code scan in PWA
- Both display matching 4-emoji fingerprint
- Server stores agent/phone public keys in Postgres
- Agent stores keypairs in OS Keychain (or file fallback) and server public key in vault
- Phone stores keypairs in IndexedDB and server public key
- Pairing tokens expire after 10 minutes and cannot be reused
- Invalid/expired tokens return appropriate errors
- SQLite vault initialized on agent machine
- All API endpoints tested (unit + integration)
- CLI pairing flow tested (mocked server)
- Biome + typecheck + tests pass
