# Clavum

*Latin: "clavum" = key*

Secret management for AI agents. Tiered access control where every secret requires at least two parties to decrypt, and the most sensitive secrets require three.

## What Is This?

AI agents need secrets — API keys, database credentials, SSH keys — but shouldn't have unencrypted access at rest. Clavum provides:

- **🟢 Green tier** — Agent + server ECDH, automatic access, cached DEKs
- **🟡 Yellow tier** — Same, but gated on human approval with cryptographic proof
- **🔴 Red tier** — Three-party key derivation: agent + server + phone must all participate

Every access request requires a reason. Every access is logged with cryptographic proof.

## Architecture

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│ Agent Machine│◄───────►│    Server    │◄───────►│    Phone     │
│   (CLI)      │  HTTPS   │  (Node.js)   │  Push +  │   (PWA)      │
│              │  + ECDH  │              │  PWA     │              │
└──────────────┘         └──────────────┘         └──────────────┘
```

- **Agent CLI** — Language-agnostic sidecar. Any AI agent framework can use it.
- **Server** — Standalone Node.js daemon. PostgreSQL + Prisma. Multi-tenant.
- **Phone PWA** — Approvals, challenge signing, ECDH for red tier.

## Documentation

- **[docs/SPEC.md](docs/SPEC.md)** — Full cryptographic specification, flows, and architecture decisions
- **[AGENT.md](AGENT.md)** — Development guidelines, testing strategy, coding standards
- **[.specify/memory/constitution.md](.specify/memory/constitution.md)** — Project principles (Spec Kit)

## Status

🚧 Early design phase. Not yet functional.

## License

AGPLv3 — see [LICENSE](LICENSE).
