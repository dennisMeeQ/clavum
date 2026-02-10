# 001 — Crypto Core: Plan

## Approach

Implement all primitives in `packages/crypto/src/` using Node.js `crypto` module. Skeleton code already exists — flesh out implementations and add comprehensive tests.

## Modules

### `src/keys.ts` (exists, needs refinement)
- `x25519.generateKeypair()` → `{ privateKey, publicKey }`
- `x25519.sharedSecret(priv, pub)` → shared secret
- `ed25519.generateKeypair()` → `{ privateKey, publicKey }`
- `ed25519.sign(priv, msg)` → signature
- `ed25519.verify(pub, msg, sig)` → boolean
- Internal: DER header constants for X25519/Ed25519 key wrapping

### `src/aes.ts` (exists, needs refinement)
- `aes256gcm.encrypt(key, plaintext, aad?, iv?)` → `{ ciphertext, tag, iv }`
- `aes256gcm.decrypt(key, ciphertext, iv, aad, tag)` → plaintext
- `aes256gcm.generateIv()` → 12 random bytes

### `src/kdf.ts` (exists, needs refinement)
- `kdf.deriveKek(ikm, salt, secretId)` → 32-byte KEK
- `kdf.deriveFingerprint(sharedSecret)` → 4 bytes
- `kdf.hmac(key, msg)` → 32-byte MAC
- `kdf.hash(data)` → 32-byte SHA-256

### `src/signatures.ts` (exists, needs refinement)
- `signatures.signRequest(priv, timestamp, method, path, body)` → signature
- `signatures.verifyRequest(pub, timestamp, method, path, body, sig, maxAge?)` → boolean
- `signatures.buildChallenge(secretId, reason, nonce?)` → challenge bytes
- `signatures.signApproval(priv, challenge)` → signature
- `signatures.verifyApproval(pub, challenge, sig)` → boolean

### `src/flows.ts` (new)
- `flows.deriveGreenKek(ephPriv, serverPub, kekSalt, secretId)` → KEK
- `flows.deriveRedKek(agentPriv, serverPub, phonePriv, challenge, secretId)` → KEK
- `flows.wrapDek(kek, dek, aad)` → `{ encryptedDek, dekIv, dekTag }`
- `flows.unwrapDek(kek, encryptedDek, dekIv, aad, dekTag)` → DEK
- `flows.encryptSecret(dek, plaintext, aad)` → `{ encryptedBlob, blobIv, blobTag }`
- `flows.decryptSecret(dek, encryptedBlob, blobIv, aad, blobTag)` → plaintext

### `src/utils.ts` (new)
- `utils.wipe(buffer)` — overwrite Uint8Array with zeros
- `utils.concat(...arrays)` — concatenate Uint8Arrays
- `utils.timingSafeEqual(a, b)` — constant-time comparison
- `utils.toBase64Url(bytes)` / `utils.fromBase64Url(str)` — encoding helpers

### `src/index.ts` (update)
- Re-export all public API

## Test Plan

### `tests/unit/keys.test.ts`
- X25519 keygen produces 32-byte keys
- X25519 ECDH: both parties derive same shared secret
- X25519 ECDH: different keypairs produce different secrets
- X25519: RFC 7748 test vectors
- Ed25519 keygen produces 32-byte keys
- Ed25519 sign/verify round-trip
- Ed25519 verify rejects wrong message
- Ed25519 verify rejects wrong public key
- Ed25519 verify rejects tampered signature
- Ed25519: RFC 8032 test vectors

### `tests/unit/aes.test.ts`
- Encrypt/decrypt round-trip
- Random IV generated when not provided
- Decrypt fails with wrong key
- Decrypt fails with tampered ciphertext
- Decrypt fails with wrong AAD
- Decrypt fails with wrong tag
- AAD is authenticated but not encrypted (data visible, integrity checked)

### `tests/unit/kdf.test.ts`
- deriveKek produces 32 bytes
- Same inputs → same KEK
- Different salt → different KEK
- Different secretId → different KEK
- deriveFingerprint produces 4 bytes
- HMAC produces 32 bytes
- SHA-256 produces 32 bytes
- SHA-256 matches known test vector

### `tests/unit/signatures.test.ts`
- signRequest/verifyRequest round-trip
- Verify rejects expired timestamp
- Verify rejects future timestamp beyond window
- Verify rejects wrong body
- Verify rejects wrong method/path
- buildChallenge contains nonce + secretId + reason hash
- buildChallenge with same inputs but different nonces → different challenges
- signApproval/verifyApproval round-trip
- Verify rejects wrong challenge

### `tests/unit/flows.test.ts`
- Green KEK derivation: agent and server derive same KEK
- Green full flow: encrypt → wrap → unwrap → decrypt recovers plaintext
- Red KEK derivation: requires all three parties
- Red KEK: different challenge → different KEK
- wrapDek/unwrapDek round-trip
- encryptSecret/decryptSecret round-trip
- unwrapDek fails with wrong KEK
- decryptSecret fails with wrong DEK

### `tests/unit/utils.test.ts`
- wipe zeros out buffer
- concat joins arrays
- timingSafeEqual returns true for equal
- timingSafeEqual returns false for unequal
- base64url round-trip

## Dependencies

- None (Node.js `crypto` only)
- Dev: `vitest`, `typescript`, `@types/node`
