# Clavum Constitution

## Core Principles

### I. Security First (NON-NEGOTIABLE)
Clavum is a security product. Every design decision, code change, and feature must be evaluated through a security lens first.
- Never log secret values, DEKs, KEKs, or private keys
- Never store KEK at rest (derived on-the-fly, wiped after use)
- Never use `Math.random()` — always CSPRNG (`crypto.getRandomValues()` / `crypto.randomBytes()`)
- Never use `==` for comparing crypto values — use constant-time comparison (`crypto.timingSafeEqual()`)
- Always wipe sensitive material from memory after use
- Always use fresh random IVs for AES-GCM (12 bytes per encryption)
- Always include AAD (`secret_id ‖ tier ‖ agent_id`) in AES-GCM operations
- Always include reason in every access request and audit log entry
- All crypto variable names must match the glossary in [`docs/SPEC.md`](../../docs/SPEC.md)

### II. Test First
- TDD mandatory: write tests → tests fail → implement → tests pass → refactor
- Coverage targets by package:
  - `@clavum/crypto`: **100%** — this is the security core, every branch matters
  - `@clavum/server`: **90%+** — integration tests against real Postgres
  - `@clavum/cli`: **80%+** — vault CRUD, pairing, offline behavior, exit codes
  - `@clavum/pwa`: **70%+** — WebCrypto unit tests + Playwright E2E
- RFC test vectors must be used where available (RFC 7748 for X25519, RFC 8032 for Ed25519)
- Failure/edge cases are as important as happy paths
- Every PR must include tests for new/changed functionality

### III. Shared Crypto Core
- All cryptographic operations live in `@clavum/crypto` — one implementation, tested once
- Server and CLI import from `@clavum/crypto`. Phone PWA uses WebCrypto API directly.
- No duplicating crypto code across packages
- When adding a new crypto operation, add it to `@clavum/crypto` with full test coverage first

### IV. Three-Component Architecture
- **Agent Machine** (CLI + SQLite vault): stores encrypted secrets, never contacts phone directly
- **Server** (Hono + Postgres): coordinates ECDH, manages approvals, stores metadata + audit. **Never stores encrypted secrets.**
- **Phone** (PWA + WebCrypto): approves requests, contributes key material for red tier
- Plaintext secrets never leave the agent machine
- Components are always treated as separate machines (even in dev)

### V. Tiered Access Model
- 🟢 **Green**: Agent + server ECDH, automatic, DEK cached with TTL
- 🟡 **Yellow**: Same + phone must sign challenge (Ed25519 approval signature)
- 🔴 **Red**: All three parties contribute key material (K_agent ‖ K_phone → KEK_red)
- Tier assignment is per-secret and immutable after creation (change requires re-storing)
- Every access requires a mandatory reason string

### VI. Simplicity Over Cleverness
- Prefer well-understood primitives (AES-256-GCM, X25519, Ed25519, HKDF-SHA256)
- No custom crypto — use platform standards (Node `crypto`, WebCrypto API). Zero external crypto dependencies.
- One tool per job: Biome for lint+format, Vitest for tests, Prisma for DB
- Start with the simplest correct implementation, optimize later

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | TypeScript (strict mode, ESM) |
| Runtime | Node.js 22+ |
| Package manager | pnpm (workspaces) |
| Server framework | Hono |
| Database | PostgreSQL + Prisma |
| Local vault | SQLite (better-sqlite3) |
| Phone app | SvelteKit PWA + WebCrypto |
| Testing | Vitest (unit/integration), Playwright (E2E) |
| Lint + Format | Biome |
| Deployment | Docker (docker-compose) |
| Crypto (Node) | Node.js `crypto` module only (X25519, Ed25519, AES-GCM, HKDF, HMAC — all built-in since Node 15+) |
| Crypto (Browser) | WebCrypto API only (no JS library fallback) |

## Monorepo Structure

```
clavum/
├── packages/
│   ├── crypto/    @clavum/crypto   Shared X25519, Ed25519, AES-GCM, HKDF
│   ├── server/    @clavum/server   Hono API + Prisma + serves PWA
│   ├── cli/       @clavum/cli      Agent-side CLI sidecar
│   └── pwa/       @clavum/pwa      SvelteKit phone app
├── prisma/        Shared Prisma schema
├── docker/        Dockerfile + docker-compose
├── AGENT.md       Development guidelines
└── biome.json     Lint + format config
```

## Coding Standards

### TypeScript
- Strict mode always
- No `any` — use `unknown` and narrow
- Explicit return types on exported functions
- Prefer `Uint8Array` over `Buffer` for crypto (cross-platform)
- Use `node:` prefix for Node built-ins

### Naming
- Files: kebab-case (`approval-request.ts`)
- Types/interfaces: PascalCase (`ApprovalRequest`)
- Variables/functions: camelCase (`deriveKek`)
- Constants: UPPER_SNAKE (`KEK_VERSION`)
- Crypto variables: snake_case matching the spec (`agent_x25519_pub`, `K_eph`, `KEK_red`)

### Test Organization
```
packages/<pkg>/
├── src/
└── tests/
    ├── unit/
    ├── integration/
    └── helpers/
```

## Cryptographic Primitives

| Primitive | Usage | Spec |
|-----------|-------|------|
| X25519 | ECDH key agreement | RFC 7748 |
| Ed25519 | Request signing, approval proof | RFC 8032 |
| AES-256-GCM | Secret encryption, DEK wrapping, KEK transport | NIST SP 800-38D |
| HKDF-SHA256 | KEK derivation from ECDH shared secret | RFC 5869 |
| HMAC-SHA256 | Approval tokens | RFC 2104 |

### Key Decisions
- Two separate keypairs per agent/phone (X25519 + Ed25519, not derived from one seed)
- Per-tenant server keypairs (not global)
- Ephemeral ECDH per secret for green/yellow (forward secrecy)
- Context-bound challenges: `random(32) ‖ secret_id ‖ SHA256(reason)`
- 60-second request signature replay window + server-side nonce dedup
- HKDF info: `"clavum-kek-v1" ‖ secret_id`
- AAD: `secret_id ‖ tier ‖ agent_id`
- Secret names stored as plaintext in vault
- 4-emoji fingerprint for pairing verification (32 bits)
- QR code payload as JSON

## Validation Gate

Before any PR is considered ready:

```bash
pnpm check          # Biome lint + format (--error-on-warnings: 0 warnings allowed)
pnpm typecheck      # tsc --noEmit all packages
pnpm --filter @clavum/pwa check  # svelte-check for PWA package
pnpm test           # all tests pass
# Or simply:
pnpm validate       # runs all of the above in sequence
```

**Requirements:**
- **Biome check** must return 0 warnings (enforced as errors via `--error-on-warnings`)
- **svelte-check** must pass for the PWA package
- All validation must be green before committing

## Git Workflow
- Main branch: `main` — always deployable
- Feature branches: `<issue-number>-<short-description>`
- Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `chore:`
- Squash merge, reference issue number
- CI: GitHub Actions — lint + typecheck + test on every PR

## Licensing
- AGPLv3 — fully open source, auditable
- Anyone can self-host. SaaS subscription for managed hosting.
- Multi-tenant from day one.

## Governance
- This constitution supersedes all other development practices
- The cryptographic specification ([`docs/SPEC.md`](../../docs/SPEC.md)) is the source of truth for all crypto flows and variable names
- Amendments require documentation and approval
- Security-related changes require extra review

**Version**: 1.0.0 | **Ratified**: 2026-02-10 | **Last Amended**: 2026-02-10
