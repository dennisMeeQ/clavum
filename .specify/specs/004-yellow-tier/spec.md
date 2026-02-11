# 004 — Yellow Tier (Phone Approval)

## Summary

Implement yellow-tier secret retrieval. Yellow tier builds on green tier: same ECDH-based KEK derivation, but the server **withholds the KEK until a paired phone signs a context-bound challenge** with Ed25519. This is cryptographic proof of human approval — not just a button tap.

## Requirements

### Storing a Yellow Secret

- Same as green tier storage (agent-local encryption, ephemeral ECDH)
- Agent registers metadata with `tier: "yellow"` on the server
- No phone involvement at storage time

### Retrieving a Yellow Secret

- Agent sends retrieval request (same as green: `eph_x25519_pub`, `kek_salt`, `reason`)
- Server detects `tier === "yellow"` and:
  1. Builds challenge: `random(32) ‖ secret_id ‖ SHA256(reason)`
  2. Creates an `ApprovalRequest` (status: pending, expires in 5 min default)
  3. Returns `{ status: "pending", approval_id, expires_at }` (HTTP 202)
  4. Notifies phone (for now: phone polls; push notifications future work)
- Agent polls `GET /api/secrets/:id/retrieve/status?approval_id=X` until resolved
- Phone polls `GET /api/approvals/pending` to discover pending requests
- Phone reviews the request (secret name, reason, requesting agent, timestamp)
- Phone approves: `POST /api/approvals/:id/approve` with `Ed25519_sign(phone_priv, challenge)`
- Server verifies signature against phone's registered `ed25519_pub`
- On valid approval:
  - Server derives KEK (same as green), encrypts with K_session
  - Stores `approval_sig` as cryptographic proof
  - Returns KEK to agent on next poll
  - Audit log: `result: human_approved`, `proof: approval_sig`
- No DEK caching for yellow tier (every access requires fresh approval)

### Rejection Flow

- Phone can explicitly reject: `POST /api/approvals/:id/reject`
- Server marks approval as `denied`, records timestamp
- Agent's next poll returns `{ status: "denied" }` → CLI exits with error
- Audit log: `result: denied`

### Expiry Flow

- Approval requests expire after configurable timeout (default: 5 minutes)
- Expired requests are resolved as `expired` on next access (lazy expiry)
- Agent's next poll returns `{ status: "expired" }` → CLI exits with error
- Audit log: `result: expired`

### Phone Authentication

- Phone authenticates to server using Ed25519 signed requests (same pattern as agent auth)
- Headers: `X-Phone-Id`, `X-Timestamp`, `X-Signature`
- Server verifies against phone's registered `ed25519_pub`
- Phone can only see/act on approvals within its tenant

### Audit Logging

- All outcomes logged: `human_approved`, `denied`, `expired`
- Approved entries include `approval_sig` as cryptographic `proof`
- Reason is always recorded
- Latency tracked (from request to resolution)

### CLI Behavior

- `clavum get <name> --reason "..."` detects yellow tier from vault record
- On `202 Pending`: prints "⏳ Waiting for phone approval..." and polls every 2 seconds
- On approval: receives KEK, decrypts, prints secret
- On denial: prints "❌ Request denied by phone" and exits 1
- On expiry: prints "⏰ Approval request expired" and exits 2
- `--timeout` flag overrides default wait (max: server-side expiry)
- `--json` output includes approval metadata

### Configuration

- `APPROVAL_TIMEOUT_MS` — server-side, default 300000 (5 min)
- Configurable per-tenant (future: per-secret)

## Non-Requirements

- No push notifications (phone polls for now)
- No red tier flows (separate spec)
- No batch approvals
- No approval delegation
- No phone PWA UI (API only in this spec; PWA is separate)

## Acceptance Criteria

- Full round-trip: store yellow → get yellow → phone approves → agent receives secret
- Phone denial → agent gets clear error, audit logged
- Expiry → agent gets timeout error, audit logged
- Approval signature is cryptographically verified (wrong key → rejected)
- Challenge is context-bound (different secret/reason → different challenge)
- No DEK caching for yellow secrets
- Phone auth works (Ed25519 signed requests)
- Phone can only see its own tenant's approvals
- Concurrent approvals work independently
- Biome + typecheck + all tests pass
