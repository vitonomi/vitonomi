# vitonomi (public repo)

Source-available (BSL 1.1) photo storage app. Self-encrypting, decentralized,
privacy-first. See workspace `../CLAUDE.md` for full project context.

## Critical boundaries

IMPORTANT: These rules are non-negotiable.

- **Encryption boundary**: ALL encryption/decryption happens in `core/`, running
  client-side. NEVER implement crypto operations in `web/` or `cli/`. The server
  never sees plaintext photos, tags, data maps, or encryption keys.
- **API boundary**: `web/` communicates with the cloud backend ONLY through the
  API defined in `docs/api-spec.yaml`. Never import cloud repo code. The
  `CloudProvider` in `web/` is a thin HTTP client.
- **Git boundary**: This repo pushes to `github.com/vitonomi/vitonomi` (public).
  Never commit secrets, API keys, or cloud-proprietary logic here.
- **Self-hosted must work**: Every feature must function without vitonomi
  infrastructure. If a code path requires the hosted API, it must have a
  self-hosted alternative path. Never break self-hosted mode.

## Architecture

```
core/           ← shared library: crypto, Autonomi client, index, types
  src/          ← source code
  tests/        ← unit + integration tests
web/            ← Next.js web app (hosted mode + self-hosted mode)
  src/          ← source code
  public/       ← static assets
  tests/        ← component + integration tests
cli/            ← standalone recovery + upload tool
  src/          ← source code
  tests/        ← tests
docs/           ← published specifications (data-format, api-spec, architecture)
```

## Commands

```bash
# Install dependencies
npm install

# Run all tests
npm test

# Run a single test file
npm test -- path/to/test.ts

# Type check
npx tsc --noEmit

# Lint
npm run lint

# Dev server (web)
cd web && npm run dev

# Local Autonomi testnet
antctl local run --build --clean --rewards-address <ETH_ADDRESS>
```

## Code style

- TypeScript strict mode, no `any` types (use `unknown` + type narrowing)
- Functions and interfaces over classes
- ES modules (`import`/`export`), never CommonJS `require()`
- Explicit error handling — no silent `catch {}` blocks; propagate or handle
- Named exports over default exports
- Import order: node builtins → third-party → local (alphabetical within groups)
- Brand name "vitonomi" is always lowercase, even at sentence start

## Testing

- **TDD**: Write tests before implementation
- **Security tests**: Every crypto operation needs tests for common attack vectors
  (key reuse, tampering, truncation, wrong-key decryption)
- **Run single tests** during development, full suite before committing
- **No mocks for crypto**: Test real encryption round-trips, not mocked operations
- **Logging**: Use structured, togglable debug logging — never `console.log`

## Storage patterns

- All storage operations go through the `StorageBackend` interface in `core/`
- Autonomi data types: Chunks (immutable, pay-once), Scratchpads (mutable 4MB,
  pay-once, free updates, monotonic counter, owner-signed)
- Self-encryption is client-side via Autonomi library — produces data map +
  encrypted chunks
- Downloads are free on Autonomi (no egress fees)

## Key decisions

- Web app mode (hosted vs self-hosted) is determined by runtime config, not build
  flags. Both modes use the same build.
- Key derivation uses Argon2id with dual salts: one for auth key (sent to
  server), one for encryption key (never leaves client). These are derived
  client-side.
- AI classification uses Venice.ai E2EE (Qwen3 VL 30B inside TEE). Fallback:
  local on-device ONNX/CLIP model.

## Compaction instructions

When compacting, always preserve: the four critical boundaries above, current
task context, list of modified files, and test commands.
