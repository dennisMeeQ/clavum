# 001 — Crypto Core

## Summary

Implement and thoroughly test all cryptographic primitives in `@clavum/crypto`. This package is the security foundation — every other feature depends on it. Zero external dependencies; uses Node.js `crypto` module only.

## Requirements

### Key Generation

- Generate X25519 keypairs (32-byte private + 32-byte public key)
- Generate Ed25519 keypairs (32-byte private + 32-byte public key)
- All key generation uses CSPRNG (`crypto.generateKeyPairSync`)
- Keys returned as raw `Uint8Array` (not DER/PEM wrappers)

### ECDH Key Agreement (X25519)

- Derive shared secret from one party's private key + other party's public key
- Both parties independently derive the same shared secret
- Shared secret is 32 bytes

### Digital Signatures (Ed25519)

- Sign arbitrary messages with a private key → 64-byte signature
- Verify signatures with the corresponding public key → boolean
- Signatures are deterministic (same input always produces same output)

### Authenticated Encryption (AES-256-GCM)

- Encrypt plaintext with a 256-bit key → ciphertext + 128-bit auth tag + 96-bit IV
- Decrypt ciphertext with the same key + IV + tag → plaintext
- Support Additional Authenticated Data (AAD) — authenticated but not encrypted
- Random IV generated per encryption (never reuse)
- Decryption fails on tampered ciphertext, wrong key, wrong AAD, or wrong tag

### Key Derivation (HKDF-SHA256)

- Derive KEK from ECDH shared secret + salt + info
- Info parameter: `"clavum-kek-v1" ‖ secret_id`
- Output: 32 bytes (256-bit KEK)
- Derive pairing fingerprint: 4 bytes from shared secret (for emoji display)

### Hashing and MAC

- SHA-256 hash of arbitrary data → 32 bytes
- HMAC-SHA256 with key + message → 32 bytes (for approval tokens)

### Request Signing

- Sign API requests: `Ed25519_sign(key, timestamp ‖ ":" ‖ method ‖ ":" ‖ path ‖ ":" ‖ hex(SHA256(body)))`
- Verify API requests: check timestamp freshness (60-second window) + verify signature
- Reject requests with timestamps outside the replay window

### Challenge Construction

- Build context-bound challenges: `random(32) ‖ secret_id ‖ SHA256(reason)`
- Challenge binds approval to a specific secret and reason
- Sign challenges (approval flow): `Ed25519_sign(key, challenge)`
- Verify challenge signatures

### KEK Derivation Flows

- **Green/Yellow KEK**: `HKDF(K_eph, kek_salt, "clavum-kek-v1" ‖ secret_id, 32)` where `K_eph = X25519(eph_priv, server_pub)`
- **Red KEK**: `HKDF(K_agent ‖ K_phone, challenge, "clavum-kek-v1" ‖ secret_id, 32)` where `K_agent = X25519(agent_priv, server_pub)` and `K_phone = X25519(phone_priv, server_pub)`

### Memory Safety

- Provide a `wipe(buffer)` utility that overwrites a Uint8Array with zeros
- All sensitive material (DEK, KEK, private keys, shared secrets) should be wipeable

## Non-Requirements

- No network I/O — this is a pure crypto library
- No storage — that's the CLI's job
- No approval logic — that's the server's job
- No WebCrypto — that's the PWA's job (separate implementation)

## Acceptance Criteria

- All primitives implemented with explicit TypeScript types
- 100% test coverage (branch + line)
- RFC test vectors used where available (RFC 7748 for X25519, RFC 8032 for Ed25519)
- Round-trip tests for every encrypt/decrypt and sign/verify pair
- Failure tests: wrong key, tampered data, expired timestamp, invalid signature
- Full KEK derivation flows tested end-to-end (green/yellow + red)
- `pnpm biome check .` passes
- `tsc --noEmit` passes
- Zero external dependencies (only `node:crypto`)
