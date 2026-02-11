# 004 — Yellow Tier: Tasks

**Depends on:** 001 (crypto core), 002 (pairing), 003 (green tier)

## Task 1: Phone auth middleware
**Files:** `packages/server/src/middleware/phone-auth.ts` (new)
- Mirror agent auth middleware for phone Ed25519 signed requests
- Extract `X-Phone-Id`, `X-Timestamp`, `X-Signature` headers
- Load phone's `ed25519_pub` from DB by phone_id
- Verify via `signatures.verifyRequest()`
- Nonce dedup (reuse existing nonce service)
- Set `c.set('phone', phone)` on Hono context
- 401 on invalid/expired/unknown, 409 on replay
- **Tests:** `tests/unit/phone-auth-middleware.test.ts`
  - Valid phone signature → passes, phone set on context
  - Invalid signature → 401
  - Expired timestamp → 401
  - Unknown phone_id → 401
  - Missing headers → 401
  - Replayed nonce → 409

## Task 2: Approval service
**Files:** `packages/server/src/services/approval.ts` (new)
- `createApproval({ secretId, phoneId, reason, timeoutMs })` → builds challenge via `signatures.buildChallenge()`, creates DB record with status `pending`
- `approveRequest(id, signature, phonePub)` → verifies signature via `signatures.verifyApproval()`, updates to `approved`, stores `approval_sig`
- `rejectRequest(id)` → updates to `denied`, sets `respondedAt`
- `getPending(tenantId)` → returns pending approvals (lazy-expires stale ones first)
- `getStatus(approvalId)` → returns current status + challenge + metadata
- `expireStale()` → bulk mark expired
- **Tests:** `tests/unit/approval-service.test.ts`
  - Create → pending with valid challenge
  - Approve with valid sig → approved, sig stored
  - Approve with invalid sig → error, stays pending
  - Reject → denied
  - Get pending excludes expired/resolved
  - Already approved → error on re-approve
  - Already denied → error on re-approve
  - Expiry: past deadline → auto-expired on status check

## Task 3: Approval API routes
**Files:** `packages/server/src/routes/approvals.ts` (new), update `app.ts`
- `GET /api/approvals/pending` — phone auth, returns pending for tenant
- `POST /api/approvals/:id/approve` — phone auth, body: `{ signature }` (base64url)
- `POST /api/approvals/:id/reject` — phone auth
- Mount on app with phone auth middleware
- **Tests:** `tests/integration/approvals.test.ts`
  - List pending → returns only pending, unexpired approvals
  - Approve with valid signature → 200
  - Approve with invalid signature → 400
  - Reject → 200
  - Phone can't approve other tenant's approvals → 404
  - Approve already-resolved → 409
  - Expired approval → 410 Gone

## Task 4: Yellow tier retrieval endpoint
**Files:** `packages/server/src/routes/secrets.ts` (modify)
- Modify `POST /api/secrets/:id/retrieve`:
  - If tier === "yellow": build challenge, find tenant phone, create approval, return 202
  - If tier === "green": existing flow (unchanged)
- Add `GET /api/secrets/:id/retrieve/status`:
  - Agent auth, query param `approval_id`
  - Check approval status:
    - `pending` (not expired) → `{ status: "pending" }`
    - `pending` (expired) → mark expired, audit → `{ status: "expired" }`
    - `denied` → audit → `{ status: "denied" }`
    - `approved` → derive KEK, encrypt for transport, audit with proof → `{ status: "approved", enc_kek, enc_kek_iv, enc_kek_tag }`
  - Verify secret belongs to requesting agent
- **Tests:** `tests/integration/yellow-retrieve.test.ts`
  - Yellow retrieve → 202 with approval_id
  - Poll pending → `{ status: "pending" }`
  - Phone approves → poll → `{ status: "approved", enc_kek... }`
  - Agent decrypts enc_kek → correct KEK → unwraps DEK → decrypts secret
  - Phone rejects → poll → `{ status: "denied" }`
  - Timeout → poll → `{ status: "expired" }`
  - Green retrieve still returns 200 (regression test)
  - Audit log entries for all outcomes with correct result types
  - Wrong agent can't poll another agent's approval → 403

## Task 5: CLI yellow tier polling
**Files:** `packages/cli/src/commands/get.ts` (modify)
- Handle 202 response from retrieval:
  - Print "⏳ Waiting for phone approval..."
  - Poll `/api/secrets/:id/retrieve/status?approval_id=X` every 2s
  - On `approved`: decrypt KEK, unwrap DEK, decrypt secret, print
  - On `denied`: print "❌ Request denied", exit 1
  - On `expired`: print "⏰ Request expired", exit 2
- Support `--timeout` flag (client-side max wait)
- `--json` includes approval_id and status in output
- **Tests:** `tests/integration/get-yellow.test.ts`
  - Yellow get → polls → approved → correct plaintext (mocked server)
  - Yellow get → denied → exit 1 + error message
  - Yellow get → expired → exit 2 + error message
  - Client timeout → exit 2
  - `--json` output structure validated

## Task 6: End-to-end yellow tier test
**Files:** `tests/integration/yellow-e2e.test.ts`
- Full flow with real server + real crypto:
  1. Create tenant + pair agent + pair phone
  2. Agent stores yellow secret
  3. Agent requests retrieval → gets 202
  4. Phone lists pending → sees approval
  5. Phone signs challenge and approves
  6. Agent polls → gets KEK → decrypts → matches original
- Also test: denial flow, expiry flow
- Verify audit log has all entries with correct proof
- **Tests:** This IS the test

## Order

```
[1] Phone auth middleware ──┐
                            ├──→ [3] Approval routes ──→ [4] Yellow retrieval ──→ [6] E2E test
[2] Approval service ───────┘                            [5] CLI polling ─────────┘
```

Tasks 1 and 2 can run in parallel.
Task 3 depends on 1 + 2.
Task 4 depends on 2 + 3.
Task 5 depends on 4.
Task 6 depends on 4 + 5.
