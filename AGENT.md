# AGENT.md — Clavum Development Guidelines

## Project Overview

Clavum is an encrypted secret manager for AI agents. Three components: agent CLI, remote server, phone PWA. Monorepo at `dennisMeeQ/clavum`.

## Tech Stack

- **Language**: TypeScript (strict mode, ESM)
- **Runtime**: Node.js 22+
- **Package Manager**: pnpm (workspaces)
- **Server**: Hono + PostgreSQL + Prisma
- **CLI**: Node.js + better-sqlite3
- **PWA**: SvelteKit + WebCrypto
- **Testing**: Vitest (unit/integration), Playwright (E2E)
- **Linting + Formatting**: Biome
- **Deployment**: Docker (docker-compose)
- **License**: AGPLv3

## Monorepo Structure

```
packages/
├── crypto/    @clavum/crypto   Shared cryptographic primitives
├── server/    @clavum/server   Hono API + Prisma + serves PWA
├── cli/       @clavum/cli      Agent-side CLI sidecar
└── pwa/       @clavum/pwa      SvelteKit phone app
prisma/        Shared Prisma schema
docker/        Dockerfile + docker-compose
```

## Coding Standards

### TypeScript
- Strict mode always (`"strict": true`)
- No `any` — use `unknown` and narrow
- Explicit return types on exported functions
- Prefer `Uint8Array` over `Buffer` for crypto operations (cross-platform)
- Use `node:` prefix for Node built-ins (`import { randomBytes } from 'node:crypto'`)

### Formatting (Biome)
- Single quotes
- Trailing commas
- Semicolons
- 100 char line width
- Tab width 2 (spaces)

### Naming
- Files: kebab-case (`approval-request.ts`)
- Types/interfaces: PascalCase (`ApprovalRequest`)
- Variables/functions: camelCase (`deriveKek`)
- Constants: UPPER_SNAKE for true constants (`KEK_VERSION`)
- Crypto variables: snake_case matching the spec (`agent_x25519_pub`, `K_eph`, `KEK_red`)

### Imports
- Group: node builtins → external packages → workspace packages → relative
- Use `.js` extension for relative imports (ESM)

## Testing Strategy

### Philosophy
- **More tests > fewer tests.** When in doubt, write the test.
- Every PR must include tests for new/changed functionality.
- Tests are documentation — they show how things work.
- Test the contract, not the implementation (except for crypto — test both).

### `@clavum/crypto` — Target: 100% coverage
This is the security core. Every branch, every edge case.
- **Primitive tests**: each function (X25519, Ed25519, AES-GCM, HKDF) tested independently
- **Round-trip tests**: encrypt → decrypt, sign → verify, keygen → ECDH
- **Failure tests**: wrong key → decrypt fails, tampered ciphertext → auth tag fails, invalid signature → verify returns false
- **RFC test vectors**: use known test vectors from RFC 7748 (X25519), RFC 8032 (Ed25519) where available
- **Challenge tests**: verify context-binding (secret_id + reason hash embedded correctly)
- **Composite tests**: full KEK derivation flows for green/yellow/red

### `@clavum/server` — Target: 90%+ coverage
- **Unit tests**: approval logic, tier routing, nonce dedup, timestamp validation
- **Integration tests**: full API flows against test Postgres
  - Green: retrieve → auto-approve → return enc_kek
  - Yellow: retrieve → challenge → approve/deny/timeout
  - Red: retrieve → challenge → phone contributes K_phone → return enc_kek
- **Auth tests**: valid signatures pass, invalid rejected, replayed rejected, expired rejected
- **Tenant isolation**: agent A cannot access agent B's metadata
- **Test DB**: separate Postgres via docker-compose (`clavum_test` database)

### `@clavum/cli` — Target: 80%+ coverage
- **Vault CRUD**: store → get → list → delete against local SQLite
- **Pairing flow**: mocked server
- **Offline behavior**: cached DEK works, uncached fails gracefully
- **Exit codes**: 0 success, 1 denial/error, 2 timeout
- **JSON output**: `--json` flag produces valid, parseable JSON with correct structure
- **Error messages**: human-readable on stderr, structured on stdout with `--json`

### `@clavum/pwa` — Target: 70%+ coverage
- **Unit tests**: WebCrypto operations (ECDH, signing) via Node webcrypto polyfill
- **E2E tests** (Playwright): pairing flow, approval flow, denial flow, timeout display
- **Visual regression**: not required initially

### Test Organization
```
packages/<pkg>/
├── src/
│   └── *.ts
└── tests/
    ├── unit/          Unit tests mirroring src/ structure
    ├── integration/   Tests requiring external services (DB, HTTP)
    └── helpers/       Shared test utilities, fixtures, mocks
```

### Test Naming
- Files: `<module>.test.ts`
- Describe blocks: module/function name
- Test names: `it('should <expected behavior> when <condition>')`

### Running Tests
```bash
pnpm test              # all packages
pnpm --filter @clavum/crypto test
pnpm --filter @clavum/server test
pnpm test:coverage     # with coverage report
```

## CI / GitHub Actions

- **On every PR**: lint (Biome) + type check (tsc) + all tests
- **On merge to main**: above + build Docker image
- **Required checks**: all must pass before merge

## Validation Gate

Before any PR is considered ready:

```bash
pnpm check                   # biome check --error-on-warnings (lint + format, 0 warnings allowed)
pnpm typecheck               # tsc --noEmit across all packages
pnpm --filter @clavum/pwa check  # svelte-check for the PWA package
pnpm build                   # build shared packages
pnpm test                    # all tests
# Or simply:
pnpm validate                # runs all of the above in sequence
```

**Requirements:**
- **Biome check** must return 0 warnings (enforced as errors via `--error-on-warnings`)
- **svelte-check** must pass for the PWA package
- All validation must be green before committing

## Crypto-Specific Guidelines

### Never
- Never log secret values, DEKs, KEKs, or private keys
- Never store KEK (derived on-the-fly, wiped after use)
- Never cache yellow/red tier DEKs
- Never use `Math.random()` for anything — always `crypto.getRandomValues()` or `crypto.randomBytes()`
- Never use `==` for comparing crypto values — use constant-time comparison

### Always
- Always wipe sensitive material from memory after use (overwrite buffers)
- Always use fresh IVs for AES-GCM (random 12 bytes per encryption)
- Always include AAD (`secret_id ‖ tier ‖ agent_id`) in AES-GCM operations
- Always verify auth tags before using decrypted data (AES-GCM does this automatically)
- Always include reason in audit logs

### Constant-Time Operations
- Use `crypto.timingSafeEqual()` for comparing MACs, signatures, tokens
- Never short-circuit on byte comparison of secrets

## Git Workflow

- **Main branch**: `main` — always deployable
- **Feature branches**: `<issue-number>-<short-description>`
- **Commits**: conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`)
- **PRs**: squash merge, reference issue number

## Documentation

- **Spec**: [`docs/SPEC.md`](docs/SPEC.md) — full cryptographic design, flows, architecture decisions
- **README.md**: user-facing docs
- **AGENT.md**: this file — development guidelines
- **Code comments**: explain *why*, not *what*. Especially for crypto operations.
- **JSDoc**: on all exported functions with param descriptions

## Reference

- Full cryptographic specification: [`docs/SPEC.md`](docs/SPEC.md)
- All variable names follow the glossary defined in the spec
- When in doubt about crypto flows, refer to `docs/SPEC.md` — it is the source of truth
