# 001 — Crypto Core: Tasks

## Task 1: Utility functions ✅
**File:** `packages/crypto/src/utils.ts` (new)
- Implement `wipe(buffer)` — overwrite Uint8Array with zeros
- Implement `concat(...arrays)` — concatenate Uint8Arrays
- Implement `timingSafeEqual(a, b)` — wrap `crypto.timingSafeEqual`
- Implement `toBase64Url(bytes)` / `fromBase64Url(str)`
- **Tests:** `tests/unit/utils.test.ts` — all functions, edge cases (empty arrays, different lengths)

## Task 2: Key generation and ECDH (X25519) ✅
**File:** `packages/crypto/src/keys.ts` (refine existing)
- Verify `x25519.generateKeypair()` produces valid 32-byte raw keys
- Verify `x25519.sharedSecret()` produces correct ECDH output
- **Tests:** `tests/unit/keys.test.ts`
  - Keygen produces 32-byte keys
  - Both parties derive same shared secret
  - Different keypairs → different secrets
  - RFC 7748 test vectors (Section 6.1)

## Task 3: Digital signatures (Ed25519) ✅
**File:** `packages/crypto/src/keys.ts` (refine existing)
- Verify `ed25519.generateKeypair()` produces valid 32-byte raw keys
- Verify `ed25519.sign()` and `ed25519.verify()` work correctly
- **Tests:** `tests/unit/keys.test.ts` (continued)
  - Keygen produces 32-byte keys
  - Sign/verify round-trip
  - Verify rejects wrong message
  - Verify rejects wrong public key
  - Verify rejects tampered signature
  - RFC 8032 test vectors (Section 7.1)

## Task 4: AES-256-GCM ✅
**File:** `packages/crypto/src/aes.ts` (refine existing)
- Verify encrypt/decrypt round-trip
- Verify AAD binding
- **Tests:** `tests/unit/aes.test.ts`
  - Encrypt/decrypt round-trip
  - Random IV auto-generated
  - Decrypt fails: wrong key
  - Decrypt fails: tampered ciphertext
  - Decrypt fails: wrong AAD
  - Decrypt fails: wrong/missing tag

## Task 5: HKDF and hashing ✅
**File:** `packages/crypto/src/kdf.ts` (refine existing)
- Verify `deriveKek()` produces deterministic 32-byte KEK
- Verify `deriveFingerprint()` produces 4 bytes
- Verify `hmac()` and `hash()` correctness
- **Tests:** `tests/unit/kdf.test.ts`
  - deriveKek: same inputs → same KEK
  - deriveKek: different salt → different KEK
  - deriveKek: different secretId → different KEK
  - deriveFingerprint: produces 4 bytes, deterministic
  - hmac: 32 bytes, deterministic
  - hash: known SHA-256 test vector

## Task 6: Request signing and challenge construction ✅
**File:** `packages/crypto/src/signatures.ts` (refine existing)
- Verify request signing/verification with replay window
- Verify context-bound challenge construction
- **Tests:** `tests/unit/signatures.test.ts`
  - signRequest/verifyRequest round-trip
  - Verify rejects expired timestamp (>60s)
  - Verify rejects wrong body/method/path
  - buildChallenge: contains nonce + secretId + reasonHash
  - buildChallenge: different nonces → different challenges
  - signApproval/verifyApproval round-trip
  - verifyApproval rejects wrong challenge

## Task 7: Composite flows (KEK derivation) ✅
**File:** `packages/crypto/src/flows.ts` (new)
- Implement `deriveGreenKek(ephPriv, serverPub, kekSalt, secretId)` → KEK
- Implement `deriveRedKek(kAgent, kPhone, challenge, secretId)` → KEK (takes pre-derived shared secrets)
- Implement `wrapDek` / `unwrapDek`
- Implement `encryptSecret` / `decryptSecret`
- **Tests:** `tests/unit/flows.test.ts`
  - Green KEK: agent ephemeral + server derive same KEK
  - Green full round-trip: encrypt → wrap → unwrap → decrypt
  - Red KEK: derived from K_agent ‖ K_phone + challenge
  - Red KEK: different challenge → different KEK
  - wrapDek/unwrapDek round-trip
  - unwrapDek fails with wrong KEK
  - encryptSecret/decryptSecret round-trip
  - decryptSecret fails with wrong DEK

## Task 8: Update exports and verify coverage ✅
**File:** `packages/crypto/src/index.ts` (update)
- Export all modules: keys, aes, kdf, signatures, flows, utils
- Run `pnpm --filter @clavum/crypto test -- --coverage`
- Verify 100% branch + line coverage
- Run `pnpm biome check .` + `pnpm typecheck`

## Order

Tasks 1-6 are independent and can be done in parallel.
Task 7 depends on 1-5.
Task 8 depends on all.

```
[1] utils ──────────────────┐
[2] X25519 ─────────────────┤
[3] Ed25519 ────────────────┤
[4] AES-GCM ────────────────┼──→ [7] Flows ──→ [8] Final
[5] HKDF ───────────────────┤
[6] Signatures ─────────────┘
```
