---
formatVersion: 2
status: stable
last-reviewed: 2026-05-03
---

# vitonomi monorepo topology

The vitonomi project lives in two repositories. This document is the
public-facing reference for that split and for the workspace layout
inside the public repo.

## The two-repo split

- **`github.com/vitonomi/vitonomi`** — the public, AGPL-3.0 repository.
  Contains every component a user runs: vault daemon, hub server,
  vitonomi-mx SMTP relay, the PWA client, the CLIs, and the shared
  Rust crate that ties them together. Everything in this doc set
  documents this repo.
- **`github.com/vitonomi/cloud`** — the private, proprietary repository.
  Contains only the hosted-service-specific layer: subscription
  billing, treasury management, internal analytics, and infrastructure-
  as-code for the hosted deployment of `vito.gg`. It depends on the
  AGPL hub through its public APIs only — there is no special
  hosted-only fork of the hub binary.
- **`github.com/vitonomi/website`** — the public, AGPL-3.0 repository
  for the vitonomi.com landing site (Astro). Standalone — no dependency
  on `vitonomi-core` or any other workspace crate.

The split exists so that:

1. Every user-runnable binary stays AGPL and auditable. Self-hosters
   never need access to anything in the private repo.
2. Hosted-service-specific commercial logic (Stripe, plan gating,
   cost-basis accounting, infra-as-code) stays out of the AGPL
   surface to keep the open-source product cleanly defined.
3. The landing site has its own release cadence and deployment
   pipeline, independent of the platform packages.

## Public-repo workspace layout

The public repo is a **Cargo workspace** for the Rust crates plus a
trimmed **npm workspace** for the PWA:

```
vitonomi/
  Cargo.toml         ← Rust workspace manifest (all binaries below)
  package.json       ← npm workspace, declares `clients/web` only
  rust-toolchain.toml
  rustfmt.toml
  clippy.toml
  deny.toml
  .cargo/config.toml
  core/              shared Rust crate — crypto, types, protocol traits
  core-wasm/         (added when PWA work begins) wasm-bindgen bridge
  vault/             vault daemon — bin: vitonomi-vault
  hub/               hub control-plane server — bin: vitonomi-hub
  mx/                vitonomi-mx SMTP relay — bin: vitonomi-mx
  vito-cli/          `vito` Rust binary — thin helper to install/manage modules
  clients/
    cli/             `vitonomi-cli` Rust binary — full CLI client
    web/             PWA (Next.js, TypeScript) — MVP. Only TS surface.
    mobile/          React Native iOS + Android — v1.1+ (not scaffolded)
    ext/             browser extensions — v1.1+ (not scaffolded)
  docs/              specification suite (this directory)
  tests/             top-level workspace integration tests
```

The `clients/` directory is the only category prefix in the layout. It
exists because there will be N sibling client surfaces (PWA, mobile,
browser extensions). Every other workspace crate is a singleton at the
top level.

> The landing site (vitonomi.com) lives in its own repository at
> `github.com/vitonomi/website`.

## Workspace dependency graph

```
core ◄── core-wasm   (wasm-bindgen bridge for clients/web)
core ◄── vault
core ◄── hub
core ◄── mx
core ◄── vito-cli
core ◄── clients/cli

vito-cli ──► (installs modules, interacts with vitonomi-cli)
clients/web ──► core-wasm  (npm dependency, built from Rust)
```

The `core` crate has no internal dependencies on other workspace
crates. Every other Rust binary depends on `core` and only on `core`
(plus shared third-party crates). The PWA (`clients/web`) depends on
the WASM build of `core` via `core-wasm`.

## Per-package layout

Each Rust crate follows the same canonical shape:

```
<crate>/
  Cargo.toml         strict; inherits from workspace lints + dependencies
  src/               implementation
    lib.rs           public re-exports + crate-level docs (libraries)
    main.rs          thin entrypoint calling lib::run() (binaries)
    cli.rs           clap::Parser definitions (binaries)
    config.rs        figment-loaded TOML config + serde struct
    ...              submodules
  tests/             integration tests (sibling directory)
  README.md          purpose, install, dev, test, gotchas
  CLAUDE.md          agent-facing rules for this crate
```

Tests live in a sibling `tests/` directory rather than colocated with
source so that `tests/security/` (for crypto crates) is a single,
auditable location.

The PWA at `clients/web/` follows Next.js conventions (TypeScript,
ESLint, vitest, etc.) and is unaffected by the Rust pivot.

## Tooling

| Concern        | Choice                                                            |
| -------------- | ----------------------------------------------------------------- |
| Language       | Rust edition 2021 (binaries) + TypeScript (PWA only)              |
| Async runtime  | `tokio`                                                           |
| Workspaces     | Cargo workspace (Rust) + npm workspaces (just `clients/web`)      |
| Build          | `cargo build --workspace`                                         |
| Test runner    | `cargo test` + `cargo nextest run` (optional, for parallelism)    |
| Linter         | `clippy` (workspace-wide pedantic + custom lints)                 |
| Formatter      | `rustfmt`                                                         |
| Dep / license  | `cargo deny` (license allow-list + per-crate dependency bans)     |
| Advisories     | `cargo audit`                                                     |
| Pre-commit     | `cargo fmt --check` + `cargo clippy` + `cargo test --lib`         |
| CI             | GitHub Actions, Linux x64 + Linux ARM64 matrix (covers the Pi)    |
| OpenAPI lint   | `spectral`                                                        |
| PWA build      | `next build` inside `clients/web` (separate from cargo)           |
| WASM bridge    | `wasm-pack build --target web` against `core-wasm/`               |
| Coverage       | `cargo-llvm-cov` (95% on `core::crypto::**`, 80% elsewhere)       |

The Rust toolchain version is pinned in `rust-toolchain.toml` and
enforced by `clippy.toml`'s `msrv` setting.

## Build commands

Per-workspace, run from the repo root:

```bash
# Setup
rustup show                              # installs the pinned toolchain

# Type / build / lint / test
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --workspace
cargo deny check
cargo audit

# Dev runs (each binary reads ~/.config/vitonomi/<bin>.toml by default)
cargo run -p vitonomi-hub   -- start
cargo run -p vitonomi-vault -- start
cargo run -p vitonomi-mx    -- start
cargo run -p vitonomi-cli   -- status

# PWA (TypeScript, npm workspace)
cd clients/web && npm install && npm run dev
```

## Cross-references

- Full per-component architecture: [`architecture.md`](architecture.md).
- Component lifecycles: [`encryption-flows.md`](encryption-flows.md).
- Wire protocols between components: [`protocol.md`](protocol.md).
- HTTP API contract: [`api-spec.yaml`](api-spec.yaml).
- Repository contributing guide: `../CONTRIBUTING.md` (in repo root,
  added in Phase 0.5 cleanup).
