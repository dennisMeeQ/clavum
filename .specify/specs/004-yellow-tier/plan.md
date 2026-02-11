# 004 — Yellow Tier: Plan

## Approach

Build on the green tier infrastructure. The main additions: phone auth middleware, approval lifecycle endpoints, modified retrieval endpoint for yellow tier, and CLI polling behavior. The Prisma schema already has `ApprovalRequest` model and `Phone` model — no migrations needed beyond what exists.

## Server Changes (`packages/server/`)

### Phone Auth Middleware (`src/middleware/phone-auth.ts`, new)

Mirror of agent auth but for phones:
- Extract `X-Phone-Id`, `X-Timestamp`, `X-Signature` from headers
- Load phone's `ed25519_pub` from DB
- Verify Ed25519 signature (same `signatures.verifyRequest` from `@clavum/crypto`)
- Nonce dedup (reuse existing nonce service)
- Set `c.set('phone', phone)` on Hono context
- Return 401 on invalid, 409 on replay

### Approval Routes (`src/routes/approvals.ts`, new)

#### `GET /api/approvals/pending`
- Auth: phone auth middleware
- Returns pending approvals for phone's tenant
- Lazy-expire: mark any past-`expiresAt` as `expired` before returning
- Response: `{ approvals: [{ id, secret_name, agent_name, reason, created_at, expires_at }] }`

#### `POST /api/approvals/:id/approve`
- Auth: phone auth middleware
- Body: `{ signature }` (base64url Ed25519 signature over challenge)
- Validates:
  - Approval exists, belongs to phone's tenant, status is `pending`, not expired
  - `signatures.verifyApproval(phone.ed25519_pub, approval.challenge, sig)` → true
- On success: update status to `approved`, store `approval_sig`, set `respondedAt`
- Return 200

#### `POST /api/approvals/:id/reject`
- Auth: phone auth middleware
- Validates: exists, belongs to tenant, status is `pending`, not expired
- Update status to `denied`, set `respondedAt`
- Return 200

### Modified Retrieval (`src/routes/secrets.ts`, update)

#### `POST /api/secrets/:id/retrieve` — handle yellow tier
- Current: only green tier (auto-approve)
- Add yellow path:
  1. Build challenge via `signatures.buildChallenge(secretId, reason)`
  2. Select phone for tenant (first phone; multi-phone selection is future work)
  3. Create `ApprovalRequest` { challenge, secretId, phoneId, reason, expiresAt }
  4. Return 202: `{ status: "pending", approval_id, expires_at }`
- Keep green path unchanged

#### `GET /api/secrets/:id/retrieve/status` (new)
- Auth: agent auth
- Query: `approval_id`
- Check approval status:
  - `pending` (and not expired) → 200 `{ status: "pending" }`
  - `pending` but expired → mark as `expired`, audit log → 200 `{ status: "expired" }`
  - `denied` → audit log (if not already logged) → 200 `{ status: "denied" }`
  - `approved` → derive KEK (same as green), encrypt for transport, audit log with proof → 200 `{ status: "approved", enc_kek, enc_kek_iv, enc_kek_tag }`
- Agent only: verify secret belongs to requesting agent

### Approval Service (`src/services/approval.ts`, new)

- `createApproval({ secretId, phoneId, reason, timeoutMs })` → ApprovalRequest
- `resolveApproval(id, status, signature?)` → updated record
- `getPending(tenantId)` → pending approvals (with lazy expiry)
- `getStatus(approvalId)` → current status + metadata
- `expireStale()` → bulk-expire past-deadline approvals (for cleanup)

## CLI Changes (`packages/cli/`)

### Modified `clavum get` (`src/commands/get.ts`, update)

- After sending retrieve request, check response status:
  - `200` (green) → same as before
  - `202` (yellow pending) → enter polling loop:
    1. Print "⏳ Waiting for phone approval..."
    2. Poll `GET /api/secrets/:id/retrieve/status?approval_id=X` every 2 seconds
    3. On `approved` → decrypt KEK, unwrap DEK, decrypt secret
    4. On `denied` → print error, exit 1
    5. On `expired` → print error, exit 2
    6. Respect `--timeout` flag (client-side max wait, default: follow server expiry)

### CLI store — no changes needed
- `clavum store <name> --tier yellow` already works (same storage flow as green)
- Metadata registers with `tier: "yellow"`

## Test Plan

### Server Unit Tests

- `tests/unit/phone-auth-middleware.test.ts`:
  - Valid phone signature → passes
  - Invalid signature → 401
  - Expired timestamp → 401
  - Unknown phone → 401
  - Replayed nonce → 409

- `tests/unit/approval-service.test.ts`:
  - Create approval → pending status
  - Approve with valid sig → approved
  - Approve with invalid sig → rejected
  - Reject → denied
  - Expire stale → expired
  - Already resolved → error

### Server Integration Tests

- `tests/integration/yellow-retrieve.test.ts`:
  - Yellow retrieval → 202 pending
  - Phone approves → agent polls → gets KEK
  - Phone rejects → agent polls → denied
  - Timeout → agent polls → expired
  - Green retrieval still works (regression)
  - Wrong phone signature → rejected
  - Audit entries for all outcomes

- `tests/integration/approvals.test.ts`:
  - Phone lists pending approvals
  - Phone approves/rejects
  - Phone can't see other tenant's approvals
  - Expired approvals don't appear in pending list

### CLI Integration Tests

- `tests/integration/get-yellow.test.ts`:
  - Yellow get → polls → approved → decrypts (mocked server)
  - Yellow get → denied → exit 1
  - Yellow get → expired → exit 2
  - `--json` output with approval metadata

## File Structure (new/modified)

```
packages/server/src/
├── routes/
│   ├── secrets.ts         (modified: yellow tier path)
│   └── approvals.ts       (new)
├── middleware/
│   ├── auth.ts            (existing: agent auth)
│   └── phone-auth.ts      (new)
└── services/
    ├── audit.ts           (existing)
    └── approval.ts        (new)

packages/cli/src/
└── commands/
    └── get.ts             (modified: polling for yellow)
```

## Dependencies

- No new packages needed
- `@clavum/crypto` already has `buildChallenge`, `signApproval`, `verifyApproval`
- Prisma schema already has `ApprovalRequest` model
