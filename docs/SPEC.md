# Clavum — Secret Management for AI Agents

*Latin: "clavum" = key*

## What Is This?

Clavum is an encrypted secret manager built for AI agents. Agents need secrets (API keys, database credentials, SSH keys) but shouldn't have unencrypted access at rest. Clavum provides tiered access control where every secret requires at least two parties to decrypt, and the most sensitive secrets require three.

**Nothing like this exists today.** Tools like HashiCorp Vault, Infisical, 1Password, and SOPS are designed for humans or CI pipelines. None offer agent-first design, tiered human approval via messaging channels, or cryptographic key splitting to a personal device.

---

## The Three Components

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│ Agent Machine│◄───────►│    Server    │◄───────►│    Phone     │
│              │  HTTPS   │   (Remote)   │  Push +  │  (Human's)   │
│              │  + ECDH  │              │  PWA     │              │
└──────────────┘         └──────────────┘         └──────────────┘
```

**Agent Machine** — where the AI runs (e.g. OpenClaw). Stores encrypted secrets locally in SQLite. Holds X25519 + Ed25519 keypairs.

**Server** — remote standalone service. Coordinates key derivation, manages approvals, stores metadata and audit logs. Holds per-tenant X25519 keypair. **Never stores encrypted secrets.**

**Phone** — human's device running a PWA. Approves requests, participates in ECDH for red tier. Holds X25519 + Ed25519 keypairs via WebCrypto.

### What Lives Where

| Data | Agent | Server | Phone |
|------|:---:|:---:|:---:|
| Encrypted secrets + wrapped DEKs | ✅ | · | · |
| Agent X25519 + Ed25519 private keys | ✅ | · | · |
| Server X25519 private key (per-tenant) | · | ✅ | · |
| Phone X25519 + Ed25519 private keys | · | · | ✅ |
| All public keys | ✅ | ✅ | ✅ |
| Secret metadata + audit log | · | ✅ | · |
| DEK cache (green, in-memory only) | ✅ | · | · |

---

## Tiered Access Model

| | 🟢 Green | 🟡 Yellow | 🔴 Red |
|---|---|---|---|
| **Use for** | Daily-use (API tokens, DB strings) | Sensitive (passwords, OAuth) | Critical (prod keys, master passwords) |
| **Parties required** | Agent + Server | Agent + Server + phone approval | Agent + Server + Phone key material |
| **Human action** | None | Approve + sign challenge | Unlock + contribute ECDH |
| **DEK caching** | ✅ TTL (4h) | ❌ Never | ❌ Never |
| **Works offline** | ✅ If cached | ❌ | ❌ |
| **Compromise: agent+server** | ⚠️ Exposed | ⚠️ Exposed | ❌ Safe |

**All tiers require a reason** for every access request. Logged + displayed to human for approval.

---

## Cryptographic Design

### Primitives

| Primitive | Usage | Spec |
|-----------|-------|------|
| **X25519** | ECDH key agreement (agent↔server, server↔phone) | RFC 7748 |
| **Ed25519** | Request signing (agent→server), approval proof (phone→server) | RFC 8032 |
| **AES-256-GCM** | Secret encryption (DEK), DEK wrapping (KEK), KEK transport | NIST SP 800-38D |
| **HKDF-SHA256** | Derive KEK from ECDH shared secret | RFC 5869 |
| **HMAC-SHA256** | Approval tokens | RFC 2104 |
| **SHA256** | Request body hashing | FIPS 180-4 |

### Key Material

#### Long-Lived (generated at pairing, stored permanently)

| Variable | Type | Location | Purpose |
|----------|------|----------|---------|
| `agent_x25519_priv` | 32B | Agent: OS Keychain / file | ECDH with server |
| `agent_x25519_pub` | 32B | All components | Public half |
| `agent_ed25519_priv` | 32B | Agent: OS Keychain / file | Sign API requests |
| `agent_ed25519_pub` | 32B | Server | Verify agent signatures |
| `server_x25519_priv` | 32B | Server: Postgres (per-tenant) | ECDH with agent + phone |
| `server_x25519_pub` | 32B | All components | Public half |
| `phone_x25519_priv` | 32B | Phone: WebCrypto/IndexedDB | ECDH for red tier |
| `phone_x25519_pub` | 32B | Server | Public half |
| `phone_ed25519_priv` | 32B | Phone: IndexedDB | Sign approval challenges |
| `phone_ed25519_pub` | 32B | Server | Verify approval signatures |

Agent uses **two separate keypairs** (X25519 + Ed25519) — same key for signing + ECDH is an anti-pattern.

#### Per-Secret (generated at storage time)

| Variable | Type | Location | Purpose |
|----------|------|----------|---------|
| `DEK` | 32B | Agent vault (encrypted) | Encrypts the actual secret value |
| `KEK` | 32B | **Never stored** | Wraps the DEK. Derived on-the-fly, wiped after use. |
| `eph_x25519_priv` | 32B | **Transient** (wiped after storage) | Forward secrecy for green/yellow |
| `eph_x25519_pub` | 32B | Agent vault | Stored so server can re-derive `K_eph` at retrieval |

#### Derived Values

| Variable | Derivation | Purpose |
|----------|------------|---------|
| `K_session` | `X25519(agent_priv, server_pub)` | Transport encryption: server → agent |
| `K_eph` | `X25519(eph_priv, server_pub)` | Green/yellow KEK derivation (ephemeral, forward-secret) |
| `K_agent` | Same as `K_session` | Red KEK derivation (named differently for clarity alongside `K_phone`) |
| `K_phone` | `X25519(phone_priv, server_pub)` | Red KEK derivation (phone's contribution) |
| `KEK_green` | `HKDF(K_eph, kek_salt, "clavum-kek-v1" ‖ secret_id, 32)` | Green/yellow DEK wrapping |
| `KEK_red` | `HKDF(K_agent ‖ K_phone, challenge, "clavum-kek-v1" ‖ secret_id, 32)` | Red DEK wrapping (3-party) |

#### Per-Request Values

| Variable | Generated by | Purpose |
|----------|-------------|---------|
| `challenge` | Server | Context-bound nonce: `random(32) ‖ secret_id ‖ SHA256(reason)`. Binds approval to specific request. |
| `request_sig` | Agent | `Ed25519_sign(agent_priv, timestamp ‖ ":" ‖ method ‖ ":" ‖ path ‖ ":" ‖ SHA256(body))` |
| `approval_sig` | Phone | `Ed25519_sign(phone_priv, challenge)` — proves human approved this specific request |
| `enc_kek` | Server | KEK encrypted for transport: `AES_GCM(K_session, KEK)` |

### Vault Record (SQLite on Agent Machine)

| Field | Type | Description |
|-------|------|-------------|
| `secret_id` | UUID v4 | Unique identifier |
| `name` | String (plaintext) | Human-readable label |
| `tier` | Enum | green, yellow, red |
| `encrypted_blob` | Bytes | `AES_GCM(DEK, plaintext, blob_iv, aad)` |
| `blob_iv` | 12B | Random IV |
| `blob_tag` | 16B | Auth tag |
| `encrypted_dek` | Bytes | `AES_GCM(KEK, DEK, dek_iv, aad)` |
| `dek_iv` | 12B | Random IV |
| `dek_tag` | 16B | Auth tag |
| `kek_salt` | 32B | Random, unique per secret |
| `eph_x25519_pub` | 32B | Ephemeral pub key (green/yellow). NULL for red. |
| `aad` | Bytes | `secret_id ‖ tier ‖ agent_id` |
| `version` | Integer | Incremented on rotation |
| `created_at` | Timestamp | |
| `updated_at` | Timestamp | |

---

## Flows

### Storage — 🟢 Green / 🟡 Yellow

```
Agent Machine
  1. DEK = random(32)
  2. blob_iv = random(12)
  3. aad = secret_id ‖ tier ‖ agent_id
  4. (encrypted_blob, blob_tag) = AES_GCM_encrypt(DEK, plaintext, blob_iv, aad)
  5. eph_x25519_priv, eph_x25519_pub = keygen()
  6. K_eph = X25519(eph_x25519_priv, server_x25519_pub)
  7. kek_salt = random(32)
  8. KEK = HKDF(K_eph, kek_salt, "clavum-kek-v1" ‖ secret_id, 32)
  9. dek_iv = random(12)
  10. (encrypted_dek, dek_tag) = AES_GCM_encrypt(KEK, DEK, dek_iv, aad)
  11. Store vault record
  12. WIPE: DEK, KEK, K_eph, eph_x25519_priv, plaintext
  13. Register metadata with server → { secret_id, name, tier }
```

Storage is entirely local — server's public key is used for ECDH but server is not contacted. Server is needed at retrieval because only it has `server_x25519_priv` to re-derive `K_eph`.

### Storage — 🔴 Red

Steps 1-4 same as above. Then:

```
Agent Machine                           Server                          Phone
  5r. Request red KEK ─────────────────>│
                                         │  6r. challenge = random(32)
                                         │      ‖ secret_id ‖ SHA256(reason)
                                         │  7r. Send challenge + reason ─>│
                                         │                                │
                                         │      8r. Human approves        │
                                         │      9r. K_phone = X25519(     │
                                         │            phone_priv, srv_pub)│
                                         │  <── K_phone ──────────────────│
                                         │
                                         │  10r. K_agent = X25519(server_priv, agent_pub)
                                         │  11r. KEK_red = HKDF(K_agent ‖ K_phone,
                                         │         challenge, "clavum-kek-v1" ‖ secret_id, 32)
                                         │  12r. enc_kek = AES_GCM(K_agent, KEK_red, random(12), "")
  <── enc_kek ───────────────────────────│  13r. WIPE: KEK_red, K_agent, K_phone
  14r. K_agent = X25519(agent_priv, server_pub)
  15r. KEK_red = AES_GCM_decrypt(K_agent, enc_kek)
  16-18. Wrap DEK, store vault record (eph_x25519_pub = NULL)
  19r. WIPE: KEK_red, K_agent, DEK, plaintext
```

Red does NOT use ephemeral keys. `challenge` as HKDF salt provides per-request uniqueness.

### Retrieval — 🟢 Green

Agent no longer has `eph_x25519_priv` (wiped for forward secrecy). Server re-derives `K_eph` and sends KEK encrypted via `K_session`.

```
Agent Machine                           Server
  1. Check DEK cache → HIT? Skip to 12
  2. request_sig = sign_request(...)
  GET /secrets/{id} + {eph_x25519_pub, kek_salt} ──────>
                                         3. verify_request(...)
                                         4. Tier: green → auto-approve
                                         5. K_eph = X25519(server_priv, eph_x25519_pub)
                                         6. KEK = HKDF(K_eph, kek_salt,
                                              "clavum-kek-v1" ‖ secret_id, 32)
                                         7. K_session = X25519(server_priv, agent_pub)
                                         8. enc_kek = AES_GCM(K_session, KEK, random(12), "")
                                         9. WIPE: K_eph, KEK
  <── enc_kek ───────────────────────────  10. audit log
  11. K_session = X25519(agent_priv, server_pub)
  12. KEK = AES_GCM_decrypt(K_session, enc_kek)
  13. DEK = AES_GCM_decrypt(KEK, encrypted_dek, dek_iv, aad, dek_tag)
  14. plaintext = AES_GCM_decrypt(DEK, encrypted_blob, blob_iv, aad, blob_tag)
  15. Cache DEK (TTL: 4h)
  16. WIPE: KEK, K_session. Plaintext wiped after use.
```

### Retrieval — 🟡 Yellow

Same as green, but server waits for phone approval before step 5:

```
  ... steps 1-4 same as green ...
                                         5. challenge = random(32) ‖ secret_id ‖ SHA256(reason)
                                         6. Send challenge + reason ──────────> Phone
  (waiting...)
                                              7. Human reads reason, taps [Approve]
                                              8. approval_sig = Ed25519_sign(phone_priv, challenge)
                                         <── approval_sig ──────────────────── Phone
                                         9. verify_approval(phone_pub, challenge, approval_sig) → true
  ... steps 5-16 same as green (but NO DEK caching at step 15) ...
  Audit log includes approval_sig as cryptographic proof.
```

Denial → `AccessDeniedError`. Timeout (5-10 min) → `TimeoutError`. No ECDH happens.

### Retrieval — 🔴 Red

All three parties participate. No ephemeral keys.

```
Agent Machine                           Server                          Phone
  1-4. Same as green
                                         5. challenge = random(32) ‖ secret_id ‖ SHA256(reason)
                                         6. Send challenge + reason ─────────> Phone
  (waiting...)
                                              7. Human taps [Unlock]
                                              8. K_phone = X25519(phone_priv, server_pub)
                                         <── K_phone ─────────────────────── Phone
                                         9. K_agent = X25519(server_priv, agent_pub)
                                         10. KEK_red = HKDF(K_agent ‖ K_phone, challenge,
                                               "clavum-kek-v1" ‖ secret_id, 32)
                                         11. enc_kek = AES_GCM(K_agent, KEK_red, random(12), "")
                                         12. WIPE: KEK_red, K_phone
  <── enc_kek ───────────────────────────
  13. K_agent = X25519(agent_priv, server_pub)
  14. KEK_red = AES_GCM_decrypt(K_agent, enc_kek)
  15. DEK = AES_GCM_decrypt(KEK_red, encrypted_dek, dek_iv, aad, dek_tag)
  16. plaintext = AES_GCM_decrypt(DEK, encrypted_blob, blob_iv, aad, blob_tag)
  17. NO caching. WIPE immediately: KEK_red, K_agent, DEK. Plaintext wiped after use.
  18. audit log
```

**K_phone transport is safe:** travels over HTTPS, useless alone (need K_agent + encrypted data). Challenge as HKDF salt ensures unique KEK_red per retrieval.

---

## Compromise Model

| Scenario | 🟢 Green | 🟡 Yellow | 🔴 Red |
|----------|:---:|:---:|:---:|
| Agent only | ❌ | ❌ | ❌ |
| Server only | ❌ | ❌ | ❌ |
| Phone only | ❌ | ❌ | ❌ |
| Agent + Server | ⚠️ **Exposed** | ⚠️ **Exposed** | ❌ Safe |
| Agent + Phone | ❌ | ❌ | ❌ |
| Server + Phone | ❌ | ❌ | ❌ |
| All three | ⚠️ | ⚠️ | ⚠️ |

No single component compromise yields anything. Green/yellow need agent+server. Red needs all three.

---

## Architecture Decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Server | Standalone Node.js daemon, PostgreSQL + Prisma, multi-tenant |
| 2 | Agent CLI | CLI sidecar (`clavum get/store/list/audit`), language-agnostic, `--json` flag |
| 3 | Phone | PWA with WebCrypto (X25519, Ed25519, AES-GCM), Web Push notifications |
| 4 | Agent ↔ Server | HTTPS/REST, Ed25519 signed requests, 60s replay window + nonce dedup |
| 5 | Server ↔ Phone | Hybrid: messaging alerts (WhatsApp/Telegram) + Web Push + PWA crypto |
| 6 | Pairing | QR code + 4-emoji fingerprint verification, single-use tokens (10 min) |
| 7 | Agent key storage | OS Keychain first, `chmod 600` file fallback. CLI warns on fallback. |
| 8 | Vault format | SQLite (`~/.clavum/vault.db`), individually encrypted secrets |
| 9 | Scope | Multi-tenant from day one (SaaS) |
| 10 | License | AGPLv3 — self-host free, managed SaaS = subscription |

### Crypto Decisions

| # | Decision | Choice |
|---|----------|--------|
| OD-1 | Agent keypairs | Two separate (X25519 + Ed25519), not derived from one seed |
| OD-2 | Server keypairs | Per-tenant (Postgres), not global |
| OD-3 | Phone crypto | WebCrypto only, no JS library fallback. Min browsers: Chrome 113+, Firefox 130+, Safari 17+ |
| OD-4 | AAD contents | `secret_id ‖ tier ‖ agent_id` |
| OD-5 | ECDH for green/yellow | Ephemeral per-secret (forward secrecy) |
| OD-6 | HKDF info | `"clavum-kek-v1" ‖ secret_id` |
| OD-7 | Red KEK on server | Acceptable (transient, milliseconds, server has no encrypted data) |
| OD-8 | Red proof flow | No separate proof needed — phone contributes K_phone before server can derive KEK |
| OD-9 | Challenge structure | Context-bound: `random(32) ‖ secret_id ‖ SHA256(reason)` |
| OD-10 | Replay window | 60 seconds + server-side nonce dedup |
| OD-11 | Approval signature scope | Signs challenge as-is (context already embedded per OD-9) |
| OD-12 | QR format | JSON (`{"pub":"base64url","token":"...","url":"..."}`) |
| OD-13 | Fingerprint | 4 emoji from set of 256 (32 bits) |
| OD-14 | Secret names | Plaintext in vault |

### Root of Trust

The Ed25519 signing key is the irreducible bootstrap secret (can't Clavum-protect the key that authenticates to Clavum). Mitigations: OS Keychain, file permissions, key pinning to machine/IP, short-lived keys with rotation, pairing requires human approval, anomaly detection.

---

## Tech Stack

| Component | Choice |
|-----------|--------|
| **Monorepo** | `dennisMeeQ/clavum` — pnpm workspaces |
| **Server** | Node.js + Hono + PostgreSQL + Prisma |
| **CLI** | Node.js (shares @clavum/crypto with server) |
| **Phone PWA** | SvelteKit + WebCrypto |
| **Deployment** | Docker (docker-compose with Postgres). Bare Node for dev. |
| **PWA hosting** | Same server — Hono serves static PWA files. One domain. |
| **Package manager** | pnpm |

### Monorepo Structure

```
clavum/
├── packages/
│   ├── crypto/    ← @clavum/crypto: shared X25519, Ed25519, AES-GCM, HKDF
│   ├── server/    ← @clavum/server: Hono API + Prisma
│   ├── cli/       ← @clavum/cli: agent-side CLI sidecar
│   └── pwa/       ← @clavum/pwa: SvelteKit phone app
├── prisma/        ← shared Prisma schema
├── docker/        ← Dockerfile + docker-compose
└── pnpm-workspace.yaml
```

### Libraries

| Component | Library | Purpose |
|-----------|---------|---------|
| Server + CLI | Node `crypto` | X25519, Ed25519, AES-256-GCM, HKDF, HMAC, CSPRNG (all built-in) |
| Server | `prisma` | PostgreSQL ORM |
| CLI | `better-sqlite3` | Agent-side vault |
| Phone PWA | WebCrypto API | X25519, Ed25519, AES-256-GCM, HKDF |

---

## Use Cases

1. **Agent needs a secret** — `clavum get <name> --reason "..."`. Tier determines flow.
2. **Human stores a secret** — via PWA or CLI on agent machine.
3. **Human rotates a secret** — store new value, version incremented.
4. **Human revokes a secret** — delete from vault.
5. **Human views audit log** — who, what, when, why, with cryptographic proof.
6. **Human denies request** — agent gets `AccessDeniedError`.
7. **Approval timeout** — treated as denial.
8. **Multiple agents** — separate keypairs, scoped access per agent.
9. **Offline agent** — green works if DEK cached; yellow/red fail gracefully.
10. **Phone lost** — recovery flow (see open questions).

---

## Open Questions

### Secret Sharing: Phone → Agent
How does the human send a new secret to the agent? Plaintext shouldn't traverse the server. Options: phone encrypts with `agent_x25519_pub`, server relays encrypted blob; direct E2E channel; via messaging (less secure).

### Backup & Recovery
Secrets exist only on agent machine. Disk death = data loss. Need: backup strategy with multi-party protection, recovery flow for machine replacement, key rotation after recovery.

### Phone Lost or Replaced
Re-establish phone keypair, server recovery mechanism, backup codes (like 2FA recovery)?

### Key Rotation
Policy for long-lived keys. Rotation without re-encrypting everything? Independent per-party rotation?

### Green Tier Constraints
Time-of-day restrictions? IP allowlists? Rate limits? Per-secret or global policy?

### Approval Fatigue
Rate limiting on requests. Batch approvals? ("Pepe wants 3 secrets for task X")

### Multi-Agent Access
Shared secrets across agents? Per-agent vaults? Agent-to-agent delegation?

---

*Version: 2026-02-10. Authors: Dennis + Pepe 🐸*
