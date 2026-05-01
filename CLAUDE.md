# vitonomi (public repo)

AGPL-3.0 self-hostable storage platform for sensitive personal data:
credentials and email aliases at MVP, more types in v1.1+. Vault daemon,
hub server, vitonomi-mx SMTP relay, PWA client, CLI, and landing site all
live here. See workspace `../CLAUDE.md` and `../PROJECT.md` for the
13-phase plan and glossary.

## Critical boundaries

IMPORTANT: These rules are non-negotiable.

- **Encryption boundary**: ALL encryption/decryption happens in `core/`,
  running client-side (browser, CLI, mobile). NEVER implement crypto in
  `clients/web/`, `cli/`, `vault/`, `hub/`, or `mx/`. The hub stores opaque
  blobs only; vaults store opaque encrypted records and chunks; the relay
  encrypts inbound mail in RAM and forwards ciphertext.
- **API boundary**: Clients communicate with the hub ONLY through the
  OpenAPI surface in `docs/api-spec.yaml`. Vault ↔ hub and client ↔ vault
  streaming protocols are in `docs/protocol.md`. Never import the private
  `cloud/` repo from any public package.
- **Git boundary**: This repo pushes to `github.com/vitonomi/vitonomi`
  (public, AGPL-3.0). Never commit secrets, API keys, or
  hosted-only/proprietary logic.
- **Self-hosted must work**: Every feature must function without vitonomi
  infrastructure. The hosted hub is just one deployment of `@vitonomi/hub`;
  the hosted relay is one deployment of `@vitonomi/mx`. Same binaries,
  no special hosted-only forks.
- **Autonomi 2.0 compatible**: vitonomi can be seen as a local buffer or cache between
  the user and the autonomi network. It is a standalone storage system but must be
  fully compatible with autonomi specs to perform periodic backups to autonomi. In
  other words: Vitonomi is a simplified version of autonomi, trimmed easy replication
  fast read & write performance, but in terms of data format fully compatible to easily
  interact with autonomi as backbone for final persistance.
  Autonomi 2.0 docs: https://github.com/WithAutonomi

## Architecture

```
core/           ← shared library: crypto, types, protocol interfaces
  src/
  tests/
vault/          ← vault daemon (Phase 3+): SQLite + filesystem + libp2p
  src/
  tests/
hub/            ← hub control-plane server (Phase 4+): Fastify + Postgres/SQLite
  src/
  tests/
mx/             ← vitonomi-mx SMTP relay (Phase 8+): log-free, RAM-only
  src/
  tests/
cli/            ← `vitonomi` CLI: wraps vault/hub/mx subcommands + recovery
  src/
  tests/
landing/        ← Astro static site for vitonomi.com
clients/        ← client surfaces (PWA, mobile, extensions)
  web/          ← PWA (Next.js, mobile-ready) — MVP
    src/
    public/
    tests/
  mobile/       ← React Native iOS+Android — v1.1+ (not scaffolded yet)
  ext/          ← browser extensions — v1.1+ (not scaffolded yet)
docs/           ← api-spec.yaml, data-format.md, protocol.md, self-hosting.md
```

## Commands

```bash
# Install
npm install

# Run all tests
npm test

# Run a single test file
npm test -- path/to/test.ts

# Type check
npx tsc --noEmit

# Lint
npm run lint

# Dev servers (per workspace)
npm run dev -w @vitonomi/web      # PWA
npm run dev -w @vitonomi/hub      # hub
npm run dev -w @vitonomi/vault    # vault
npm run dev -w @vitonomi/mx    # mx
npm run dev -w @vitonomi/landing  # landing
```

## Code style

- TypeScript strict mode, no `any` (use `unknown` + type narrowing)
- Functions and interfaces over classes
- ES modules (`import`/`export`), never CommonJS `require()`
- Explicit error handling — no silent `catch {}` blocks
- Named exports over default exports
- Import order: node builtins → third-party → local (alphabetical)
- Brand name "vitonomi" is always lowercase, even at sentence start

## Testing

- **TDD**: Write tests before implementation
- **Security tests**: Every crypto operation needs tests for common attack
  vectors (key reuse, tampering, truncation, wrong-key decryption, PQ
  algorithm-confusion, cluster-admin/user signature isolation)
- **Privacy assertion tests**: relay process must hold zero plaintext on
  disk and zero plaintext in logs (verified by inotify probe + log scan)
- **No mocks for crypto**: Test real round-trips, not mocked operations
- **Run single tests** during development, full suite before committing
- **Logging**: structured, togglable — never `console.log`

## Storage and protocol patterns

- All vault local storage goes through the `VaultStorage` interface in
  `core/`. Implementations: `SqliteVaultStorage` (vault daemon),
  `InMemoryVaultStorage` (tests).
- All client → hub access goes through the `HubControlPlane` interface.
  Implementations: `HostedHubClient` (HTTP), `InMemoryHubControlPlane`
  (tests).
- All client → vault access goes through `VaultRpc` over libp2p streams.
  Authentication via short-lived session tokens issued by the hub.
- Mutable per-user, per-data-type state is a **snapshot chain**: each
  publish is an AEAD-encrypted, ML-DSA-65-signed envelope chained via
  `prevAddress`. Per-record framing inside snapshots so concurrent
  non-overlapping edits merge without shadowing.
- Head pointer (address + seq) is stored encrypted on the hub
  (`/library/head`), in IndexedDB (web), in a local file (CLI), and on the
  user's seed-phrase backup file. Server rejects `PUT` with a `seq` lower
  than the stored value (rollback protection).
- Replication: main vault accepts the snapshot, fans out to peer vaults
  over libp2p; peer vaults pull lazily; failover promotes any peer to main.

## Key decisions

- **Mode (hosted vs self-hosted)** is determined by runtime config, not
  build flags. Both modes use the same build.
- **Argon2id dual-key**: auth key sent to hub, encryption key never leaves
  client. Run in a Web Worker in the PWA.
- **Cluster admin** is a distinct ML-DSA-65 keypair derived from the seed of
  the cluster creator. Family members invited via signed invite tokens.
  Per-user quotas enforced by vaults via labelled byte counts.
- **Email aliases** receive-only at MVP. Default aliases are
  `<handle>@<username>.vito.gg` (each user picks a personal subdomain at
  registration). Custom domains supported via one-time DNS-verified
  ownership (TXT challenge + MX records). Each alias has its own
  ML-KEM-768 pubkey published in the hub directory; the relay encrypts
  to it on receive and pushes ciphertext.
- **Post-quantum** end-to-end. ML-DSA-65 for signatures, ML-KEM-768 for
  KEM, XChaCha20-Poly1305 + Argon2id at 256-bit symmetric keys.

## Compaction instructions

When compacting, always preserve: the four critical boundaries, current
task context, list of modified files, and test commands.
