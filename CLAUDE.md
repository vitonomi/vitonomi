# vitonomi (public repo)

AGPL-3.0 self-hostable storage platform for sensitive personal data:
credentials and email aliases at MVP, more types in v1.1+. Vault daemon,
hub server, vitonomi-mx SMTP relay, PWA client, and CLIs all live here.
The landing site lives in its own repo at `github.com/vitonomi/website`.
See workspace `../CLAUDE.md` and `../PROJECT.md` for the 13-phase plan
and glossary.

## Critical boundaries

IMPORTANT: These rules are non-negotiable.

- **Hub-blindness**: The hosted hub MUST NEVER read plaintext user
  data, including metadata. Stricter than zero-knowledge-of-content;
  also zero-knowledge-of-membership, zero-knowledge-of-username,
  zero-knowledge-of-admin-actions. The hub reads only `cluster_id`,
  public keys, opaque random ids, connection-observable state, and
  signed envelope shells with sealed bodies (chain entries, invite
  outer summaries). Everything else (username → `lookup_id`, vault
  names, admin chain payloads, Argon2 salts, invite inner payloads)
  is sealed. See `docs/architecture.md#hub-blindness-trust-topology`.
- **Encryption boundary**: ALL encryption / decryption / key derivation
  happens in the `core` Rust crate (or in `core-wasm/` for browser
  consumption), running client-side (browser, CLI, mobile). NEVER
  implement crypto in `clients/web/`, `clients/cli/`, `vito-cli/`,
  `vault/`, `hub/`, or `mx/`. The hub stores opaque blobs only; vaults
  store opaque encrypted records and chunks; the relay encrypts inbound
  mail in RAM and forwards ciphertext. The boundary is enforced by
  `cargo deny` rules in `deny.toml` that ban direct dependencies on
  `pqcrypto-*`, `chacha20poly1305`, `argon2`, `hkdf`, and `sha2`
  outside `core`.
- **API boundary**: Clients communicate with the hub ONLY through the
  OpenAPI surface in `docs/api-spec.yaml`. Vault ↔ hub and client ↔ vault
  streaming protocols are in `docs/protocol.md`. Never import the private
  `cloud/` repo from any public crate.
- **Git boundary**: This repo pushes to `github.com/vitonomi/vitonomi`
  (public, AGPL-3.0). Never commit secrets, API keys, or
  hosted-only/proprietary logic.
- **Self-hosted must work**: Every feature must function without vitonomi
  infrastructure. The hosted hub is just one deployment of `vitonomi-hub`;
  the hosted relay is one deployment of `vitonomi-mx`. Same binaries,
  no special hosted-only forks.
- **Autonomi 2.0 compatible**: vitonomi can be seen as a local buffer or
  cache between the user and the autonomi network. It is a standalone
  storage system but must be fully compatible with autonomi specs to
  perform periodic backups to autonomi. Because vitonomi and Autonomi
  share a Rust + libp2p-rs stack, integration is direct (consume
  upstream `self_encryption` and `autonomi` crates) — no JS port to
  maintain. Autonomi 2.0 docs: https://github.com/WithAutonomi

## Architecture

```
Cargo.toml          ← Rust workspace manifest (all binaries below)
package.json        ← npm workspace, declares clients/web only
core/               ← shared Rust crate: crypto, types, protocol traits
  src/
  tests/
core-wasm/          ← (added when PWA work begins) wasm-bindgen bridge
  src/
vault/              ← vault daemon Rust binary (Phase 3+):
  src/              ← `vitonomi-vault` (sqlx + filesystem + libp2p-rs later)
  tests/
hub/                ← hub control-plane server Rust binary (Phase 4+):
  src/              ← `vitonomi-hub` (axum + sqlx + Postgres/SQLite + rustls)
  tests/
mx/                 ← vitonomi-mx SMTP relay Rust binary (Phase 8+):
  src/              ← log-free, RAM-only SMTP receiver
  tests/
vito-cli/           ← `vito` CLI Rust binary: thin helper to install/manage modules
  src/
  tests/
clients/            ← client surfaces
  cli/              ← `vitonomi-cli` Rust binary: full CLI client
    src/
    tests/
  web/              ← PWA (Next.js, TypeScript) — MVP
    src/
    public/
    tests/
  mobile/           ← React Native iOS+Android — v1.1+ (not scaffolded yet)
  ext/              ← browser extensions — v1.1+ (not scaffolded yet)
docs/               ← api-spec.yaml, data-format.md, protocol.md, self-hosting.md
tests/              ← top-level workspace integration tests (mini_mvp_integration.rs etc.)
```

## Commands

```bash
# Install Rust toolchain (uses ./rust-toolchain.toml)
rustup show

# Run all Rust tests
cargo test --workspace

# Run a single test file or module
cargo test -p vitonomi-core path::to::test_name

# Type check / build check
cargo check --workspace --all-targets

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --check

# Dependency / license audit
cargo deny check
cargo audit

# Per-binary dev run (reads ~/.config/vitonomi/<bin>.toml by default)
cargo run -p vitonomi-hub   -- start
cargo run -p vitonomi-vault -- start
cargo run -p vitonomi-mx    -- start
cargo run -p vitonomi-cli   -- status

# PWA (TypeScript, npm-only)
cd clients/web && npm install && npm run dev
```

## Code style

- Rust edition 2021, MSRV pinned in `rust-toolchain.toml`.
- `#![deny(unsafe_code)]` on every non-FFI crate.
- `clippy::pedantic = "warn"`, `clippy::unwrap_used = "deny"`,
  `clippy::expect_used = "deny"` workspace-wide (relaxed under
  `#[cfg(test)]`).
- Errors are `thiserror::Error` enums with discriminator variants. No
  `unwrap()` or `expect()` outside tests; propagate with `?`.
- Functions and traits over inheritance; `enum` + `match` for closed
  sets; newtype wrappers for branded primitives (`ClusterId`, `UserId`,
  `Username`, etc.).
- Module layout follows cargo defaults: `src/lib.rs` re-exports public
  API; submodules in sibling files or `mod.rs`.
- Public items get `///` rustdoc with at least a one-line summary;
  security-relevant items get an `# Examples` block too.
- `rustfmt.toml` enforces formatting; never hand-format around the
  tool.
- Brand name: "vitonomi" (lowercase) in running text; "Vitonomi" is
  fine at sentence start.

## Testing

- **TDD**: Write tests before implementation.
- **Security tests**: Every crypto operation needs tests for common
  attack vectors (key reuse, tampering, truncation, wrong-key
  decryption, PQ algorithm-confusion, cluster-admin/identity signature
  isolation, admin-chain hash-link tampering).
- **Privacy assertion tests**: relay process must hold zero plaintext
  on disk and zero plaintext in logs (verified by inotify probe + log
  scan).
- **No mocks for crypto**: Test real round-trips, not mocked
  operations. The `core` crate's `test-crypto` feature swaps in a
  faster Argon2id profile (m=8 MiB, t=1) for tests; production builds
  must use the prod profile (m≥256 MiB).
- **Run single tests** during development (`cargo test
  test_name_substring`), full suite before committing
  (`cargo test --workspace`).
- **Property-based tests** via `proptest` for crypto round-trips and
  protocol invariants.
- **Logging**: structured `tracing` events. Never `println!` /
  `eprintln!` in library code.

## Storage and protocol patterns

- All vault local storage goes through the `VaultStorage` trait in
  `core`. Implementations: `SqliteVaultStorage` (vault daemon),
  `InMemoryVaultStorage` (tests).
- All client → hub access goes through the `HubControlPlane` trait.
  Implementations: `HostedHubClient` (HTTP via `reqwest` +
  `rustls-tls`), `InMemoryHubControlPlane` (tests).
- All client → vault access goes through `VaultBus` over libp2p-rs
  streams (target) — currently WebSocket-over-TLS via
  `tokio-tungstenite`. Authentication via short-lived session tokens
  issued by the hub plus signed challenge frames.
- Mutable per-user, per-data-type state is a **snapshot chain**: each
  publish is an AEAD-encrypted, ML-DSA-65-signed envelope chained via
  `prev_address`. Per-record framing inside snapshots so concurrent
  non-overlapping edits merge without shadowing.
- Head pointer (address + seq) is stored encrypted on the hub
  (`/v1/library/head`), in IndexedDB (web), in a local file (CLI), and
  on the user's seed-phrase backup file. Server rejects `PUT` with a
  `seq` lower than the stored value (rollback protection).
- Replication: main vault accepts the snapshot, fans out to peer vaults
  over libp2p-rs; peer vaults pull lazily; failover promotes any peer
  to main.
- **Cluster identity** is rooted in the seed phrase, not the hub:
  `cluster_id = sha256(cluster_admin_pubkey || format_version)`. Admin
  chain entries (signed by the cluster admin sk) are replicated to
  every vault, so the cluster survives any hub failure / migration.

## Key decisions

- **Mode (hosted vs self-hosted)** is determined by runtime config, not
  build flags. Both modes use the same binary.
- **Per-binary TOML configs** at `$XDG_CONFIG_HOME/vitonomi/<bin>.toml`
  (override with `--config <path>`). Layered via `figment`: defaults →
  config file → env (`VITONOMI_*`) → CLI flags. Each binary ships an
  `init` subcommand that writes a default config interactively or from
  flags so first-time setup is one command.
- **Argon2id**: Scheme A login — server stores public key + encrypted
  key blob, never sees `auth_key`. Login is a challenge-response signed
  with the identity sk recovered from the blob.
- **Cluster admin** is a distinct ML-DSA-65 keypair derived from the
  seed of the cluster creator. Family members invited via signed
  invite tokens. Per-user quotas enforced by vaults via labelled byte
  counts.
- **Email aliases** receive-only at MVP. Default aliases are
  `<handle>@<username>.vito.gg` (each user picks a personal subdomain at
  registration). Custom domains supported via one-time DNS-verified
  ownership (TXT challenge + MX records). Each alias has its own
  ML-KEM-768 pubkey published in the hub directory; the relay encrypts
  to it on receive and pushes ciphertext.
- **Post-quantum** end-to-end. ML-DSA-65 for signatures, ML-KEM-768 for
  KEM, XChaCha20-Poly1305 + Argon2id at 256-bit symmetric keys.
- **Username** (not email) is the canonical user identifier. Format:
  lowercase alphanumeric + `-` + `_`, length 3–32, case-insensitive.
  DNS-safe by construction.

## Compaction instructions

When compacting, always preserve: the four critical boundaries, current
task context, list of modified files, and test commands.
