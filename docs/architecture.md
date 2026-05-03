---
formatVersion: 1
status: draft
last-reviewed: 2026-05-01
---

# vitonomi system architecture

vitonomi is a privacy-first, self-hostable storage platform for
sensitive personal data. Users hold their own keys; servers see
opaque ciphertext only; data lives in user-controlled storage. The
chunk and DataMap formats are byte-for-byte compatible with the
Autonomi 2.0 network so chunks can flow into the network as an
additional replica target without format migration.

This document is the mental model. Read it first; every other spec in
this suite assumes the vocabulary and component split established here.

## Components

### Vault — `vitonomi-vault`

A long-running daemon that stores opaque encrypted chunks and the
metadata needed to address them. Runs on home servers, NAS hardware,
VPS instances, or any always-on machine the user controls. A single
user typically runs ≥2 vaults for replication.

- **Role.** Persistent encrypted storage. Each chunk is content-
  addressed in Autonomi 2.0 format.
- **Language.** Rust edition 2021, MSRV pinned in
  `rust-toolchain.toml`. Async via `tokio`.
- **Storage.** SQLite (via `sqlx` with compile-time-checked queries)
  for chunk-metadata index; filesystem for raw encrypted chunk bytes
  (sharded directory layout matching Autonomi's recommended on-disk
  shape).
- **Network.** Speaks libp2p-rs (QUIC + Noise) to peer vaults and to
  clients (target). Dials the hub outbound (currently
  WebSocket-over-TLS via `tokio-tungstenite`; libp2p-rs upgrade in a
  later phase) — never accepts inbound from the hub.
- **What it can read.** Nothing. Chunks are AEAD-then-self-encrypted
  client-side; the vault holds opaque bytes.
- **What it cannot read.** User content, user metadata, encryption
  keys, signing keys.

### Hub — `vitonomi-hub`

The control-plane server. Holds opaque metadata only — encrypted
key blobs, encrypted head pointers, the alias-pubkey directory, the
vault directory, and admin chains. Brokers introductions between
clients and vaults (libp2p rendezvous).

- **Role.** Coordination, discovery, opaque-blob storage, NAT-traversal
  rendezvous.
- **Language.** Rust edition 2021. `axum` web framework on `tokio`,
  with `tower` / `tower-http` middleware and `rustls` for TLS.
- **Storage.** PostgreSQL (multi-tenant hosted) or SQLite
  (single-user self-hosted), via `sqlx` with compile-time-checked
  queries.
- **Network.** HTTP/HTTPS for the OpenAPI client surface; persistent
  WebSocket inbound from vaults via `axum`'s `ws` module
  (length-prefixed CBOR frames); authenticated push from mx.
- **What it can read.** Opaque encrypted blobs, plaintext metadata
  (vault multiaddrs, alias pubkeys, plan tier, last-seen timestamps,
  byte-count usage).
- **What it cannot read.** User content, encryption keys, signing
  keys.

### vitonomi-mx — `vitonomi-mx`

An SMTP relay that receives mail addressed to vitonomi-hosted aliases.
Stateless, log-free, RAM-only: messages are AEAD-encrypted in memory
during the SMTP DATA phase, then run through self-encryption, then
pushed to the recipient's hub as ciphertext. The mx process never
writes plaintext to disk and never logs message content.

- **Role.** SMTP receiver + on-the-fly encrypt-and-forward.
- **Language.** Rust edition 2021 (`tokio` async runtime; SMTP via
  a Rust SMTP crate, encryption via the `core` crate).
- **Storage.** None. Stateless.
- **Network.** Inbound SMTP on port 25 (and submission on 587 for
  v1.1 outbound). Outbound: authenticated push to the hub.
- **What it can read.** A single message in process memory during
  DATA-phase reception. Released as soon as the encrypt-and-forward
  cycle completes.
- **What it cannot read.** Anything outside that DATA-phase window.
  Anything once a message is written to ciphertext.

### Clients

User-facing applications that hold the user's keys, drive
encryption/decryption, and present UI.

- **`clients/web`** — Next.js App Router PWA, mobile-ready,
  installable. **TypeScript** (the only TS surface in the project).
  Argon2id and PQ crypto run in a Web Worker, using a WASM build of
  the Rust `core` crate (`core-wasm/`) — no parallel JS crypto
  implementation. libp2p-rs (compiled to WASM) uses WebTransport
  (primary) or WebRTC (fallback) to reach the user's main vault.
- **`clients/cli`** — `vitonomi-cli` Rust binary. Standalone tool
  that depends on the `core` crate. Recovery commands
  (`vitonomi-cli cluster restore`) re-derive keys from the seed
  phrase via `core`.
- **`vito-cli`** — `vito` Rust binary; thin helper CLI that
  installs/manages vitonomi modules and dispatches to the
  user-facing daemons.
- **`clients/mobile`** (v1.1+) — React Native iOS + Android, sharing
  the WASM-compiled Rust `core` crate (or, where possible, native
  bindings via UniFFI / `napi-rs`) for crypto and protocol.
- **`clients/ext`** (v1.1+) — Browser extensions for credential
  autofill (Chrome + Firefox manifests; same TypeScript code,
  consuming the same `core-wasm` package).

### Autonomi network

The decentralised storage network vitonomi targets for compatibility.
Vitonomi chunks are byte-for-byte Autonomi 2.0 format. In MVP, no
network calls are made — chunks live only on vitonomi-vault disks.
In v1.1, the `AutonomiBridge` interface is wired to a real
`@autonomi/client` and chunks are pushed as an additional replica
target.

See [`autonomi-compat.md`](autonomi-compat.md) for the
compatibility statement.

## Trust boundaries

vitonomi enforces these invariants cryptographically; they are not
policy decisions.

| Component              | Cannot read               | Why                                                                    |
| ---------------------- | ------------------------- | ---------------------------------------------------------------------- |
| Hub                    | User content, keys        | Stores AEAD-encrypted blobs only; never receives plaintext             |
| Vault                  | User content, keys        | Stores AEAD-then-self-encrypted chunks; user holds the AEAD key        |
| Peer vault             | Other users' content      | Per-user labelling; AEAD key is user-specific                          |
| mx                     | User content (post-relay) | Plaintext exists only in process RAM during DATA phase                 |
| vitonomi (the company) | Any user's content        | None of the above components ever decrypt                              |
| Cluster admin          | Other members' content    | Each member holds their own keys; admin can see usage byte-counts only |

## Single-cluster topology

```
                     ┌────────────────────────────────┐
                     │            HUB                 │
                     │  (control plane, opaque blobs) │
                     │                                │
                     │  - alias directory             │
                     │  - vault directory             │
                     │  - encrypted key blobs         │
                     │  - encrypted head pointers     │
                     │  - admin chains                │
                     └────────────┬───────────────────┘
                                  │ websocket/QUIC outbound
                                  │ (vaults dial; hub never inbound)
                                  ▼
                            ┌──────────┐
                  ┌──────── │  VAULT   │ ────── ... ─── (peer vaults)
                  │         │ (main)   │
                  │         └──────────┘
                  │              ▲
                  │ libp2p        │ libp2p replication
                  │ (rendezvous   │ fanout (main → peer)
                  │  via hub)     │
                  ▼              │
            ┌──────────┐         │       ┌──────────┐
            │  CLIENT  │         └────── │  VAULT   │
            │  (PWA /  │                 │  (peer)  │
            │   CLI)   │                 └──────────┘
            └──────────┘

       ┌──────────────────┐    POST /v1/mx/messages
       │   vitonomi-mx    │ ──────────────────────────► HUB
       │  (SMTP receiver) │     (authenticated push)
       └──────────────────┘
              ▲
              │ inbound SMTP (port 25)
              │ from external mail servers

       ┌──────────────────┐
       │  Autonomi network│  (v1.1: vault pushes chunks here as
       │     (v1.1)       │   an additional replica target)
       └──────────────────┘
```

## Deployment modes

vitonomi supports four deployment modes from the same binaries:

1. **Hosted.** vitonomi runs the hub at `hub.vitonomi.com` and
   vitonomi-mx for `*.vito.gg`. The user runs vaults on their own
   hardware. Subscription required.
2. **Self-hosted.** The user runs hub + mx + vaults on their own
   infrastructure (likely all on one host for personal use). No
   subscription, no vitonomi dependency.
3. **Hybrid.** The user runs vaults at home but uses the hosted
   hub + mx for convenience. Subscription required.
4. **Custom domain on hosted infra.** The user uses the hosted
   hub + mx but receives mail at their own domain (DNS-verified
   ownership). Subscription required.

Self-hosted is the acid test: every feature must work without any
vitonomi infrastructure reachable.

## Data lifecycle (executive summary)

1. **Plaintext on client.** A record (credential, alias config,
   alias message) is built per the schema in
   [`record-types.md`](record-types.md).
2. **AEAD-encrypt with user key.** XChaCha20-Poly1305 with random
   nonce, key derived from password via Argon2id (dual-salt).
3. **Self-encrypt.** Run the AEAD ciphertext through the upstream
   `@autonomi/self-encryption` library to get N encrypted chunks
   plus a DataMap. The DataMap is the secret needed to reassemble
   and decrypt; the chunks are content-addressed.
4. **Chunks → vault store.** Each chunk is written to the user's
   main vault (and replicated to peer vaults via libp2p). In v1.1,
   chunks also flow to the Autonomi network.
5. **DataMap → snapshot → snapshot chain.** The DataMap is wrapped
   in a RecordFrame and added to a snapshot envelope. The envelope
   itself is AEAD-encrypted and self-encrypted, producing
   snapshot-chunks and a snapshot-DataMap. The new head pointer
   (containing the inline snapshot-DataMap, seq, and signature) is
   AEAD-encrypted and PUT to the hub.

Reading reverses the same steps.
[`encryption-flows.md`](encryption-flows.md) has the full per-action
flow with primitive-level detail.

## Cross-cutting concerns

- **Post-quantum cryptography end to end.** ML-DSA-65 (signatures),
  ML-KEM-768 (key encapsulation), XChaCha20-Poly1305 (AEAD), Argon2id
  (KDF), HKDF-SHA-256 (key derivation), BLAKE3 (chunk addressing,
  pinned via upstream). No Ed25519, no X25519.
- **Recovery model.** Seed phrase + AEAD-encrypted key blob + AEAD-
  encrypted head pointer = full recovery. Three storage tiers for the
  head pointer (hub, IndexedDB, seed-phrase backup file); first
  available wins.
- **Multi-user clusters.** A cluster admin invites family members
  via signed invite tokens. Members hold their own encryption keys;
  the admin can see aggregated usage but cannot decrypt member
  content.
- **libp2p-rs transport.** QUIC primary, WebTransport for browsers
  (compiled to WASM), WebRTC fallback. Hub-mediated rendezvous for
  NAT traversal. Mini-MVP and early phases use plain
  WebSocket-over-TLS via `tokio-tungstenite` — the swap to libp2p-rs
  is a single constructor change at the `VaultBus` trait boundary.
- **Self-hosted parity.** Every feature works without vitonomi
  infrastructure. The hosted offering is one deployment of the same
  AGPL binaries.

## Stability promise

| Spec              | formatVersion   | Stability                                                    |
| ----------------- | --------------- | ------------------------------------------------------------ |
| `architecture.md` | 1               | Reviewed by Phase 12; conceptual stability target.           |
| `data-format.md`  | 1 (incremental) | Stable from each phase deliverable forward.                  |
| `protocol.md`     | 1               | `/1` URL prefix on all stream protocol IDs; bump = breaking. |
| `api-spec.yaml`   | 1               | `/v1/` URL prefix; `/v2/` for breaking changes.              |

Once a record is written under format version N, it MUST remain
readable by every subsequent vitonomi release that supports format N.

## Out of scope at this layer

- Specific Autonomi network payment flow — see
  [`autonomi-compat.md`](autonomi-compat.md) and the v1.1 deferred
  features in `PROJECT.md`.
- Cloud subscription billing — proprietary, lives in
  `cloud/billing/`.
- The static-site build of `docs.vitonomi.com` — Phase 12.
