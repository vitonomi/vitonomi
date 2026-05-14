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

| Component              | Cannot read                                | Why                                                                    |
| ---------------------- | ------------------------------------------ | ---------------------------------------------------------------------- |
| Hub                    | User content, **keys, and metadata**       | Hub-blindness invariant — see below                                    |
| Vault                  | User content, keys                         | Stores AEAD-then-self-encrypted chunks; user holds the AEAD key        |
| Peer vault             | Other users' content                       | Per-user labelling; AEAD key is user-specific                          |
| mx                     | User content (post-relay)                  | Plaintext exists only in process RAM during DATA phase                 |
| vitonomi (the company) | Any user's content + metadata              | The hub-blindness invariant binds the hosted hub too                   |
| Cluster admin          | Other members' content                     | Each member holds their own keys                                       |

## Hub-blindness (trust topology)

**Binding invariant.** The hub — including the hosted deployment at
`hub.vitonomi.com` — MUST NEVER read plaintext user data, including
**metadata**. This is stricter than zero-knowledge-of-content; it is
also zero-knowledge-of-membership, zero-knowledge-of-username, and
zero-knowledge-of-admin-actions.

The hub is allowed to read only the absolute minimum coordination
metadata:

- `cluster_id` (32-byte hash, no info content) — for routing.
- Public keys (ML-DSA-65 / ML-KEM-768) — public by definition;
  needed to verify signatures at the WS handshake gate and at the
  invite admission gate.
- Opaque random ids (`user_id`, `vault_id`, `session_id`,
  `invite_nonce`, `challenge_id`).
- Connection-observable state (`last_seen` ts from heartbeats,
  online/offline status, hashed remote IP). Inherent to the WS
  broker role.
- Signed-envelope shells with sealed bodies — chain entries
  `{ cluster_id, seq, prev_hash, sealed_blob, sig_admin_outer }`
  and invite outer summaries
  `{ cluster_id, invite_nonce, expires_at_ms, inner_payload_hash,
    sig_admin_outer }`. The hub verifies `sig_admin_outer` against
  the cluster admin pubkey to gate admission; the inner body stays
  opaque.
- Reserved `format_version`, `key_epoch`, `admin_pubkey_epoch`
  fields (no info content).

Everything else is sealed. See [`data-format.md`](data-format.md)
for the byte layouts.

### Cluster shared key

A 32-byte symmetric key, **HKDF-derived deterministically from the
BIP-39 seed** (info `"vitonomi/cluster_shared_key/v1"`). Distributed
to vaults via the **K2 invite-inner-payload** mechanism (the cluster
shared key is sealed inside the invite token's inner payload, which
travels admin → vault operator out-of-band). All cluster-scoped
metadata (vault directory entries, admin chain payloads) is
AEAD-sealed under this key.

### `cluster_pepper`

A 32-byte secret HKDF-derived from the BIP-39 seed (info
`"vitonomi/cluster_pepper/v1"`) and stored ONLY inside the
encrypted key blob. Used to construct `user_lookup_id =
argon2id(username || cluster_pepper, salt=cluster_id, m=32 MiB,
t=2)`. Forces a malicious hub to defeat both Argon2 cost AND a
256-bit guess to enumerate usernames; blocks cross-cluster
correlation entirely.

### Chain integrity is a vault property, not a hub property

The hub stores admin chain envelopes, but it cannot be trusted to
serve "the chain" under hub-blindness. A hosted operator can:
- **Suppress.** Refuse to serve a recent entry; return an older
  head.
- **Fork.** If the admin signs two entries at the same `(seq,
  prev_hash)`, serve one to vault A and the other to vault B.
- **Replay an old prefix.** Hand a brand-new vault during
  enrollment a truncated prefix that hides revocations.

Mitigations are normative:

1. **Vault peer gossip.** The vault-bus emits a `ChainAdvertise
   { highest_seq, head_hash }` frame on every reconnect; vaults
   log + alert on regression vs. local state and request peer
   copies via the data plane.
2. **Cluster restore from vaults only.** `vitonomi-cli cluster
   restore` accepts chain exports from a vault, never from the
   dying hub (which may be malicious).
3. **Single-vault downgrade.** N=1 clusters have no peer to
   gossip with. The CLI MUST auto-export the latest chain to the
   seed-phrase backup file at every login and warn when the
   backup is stale > 7 days. Without the offline copy,
   single-vault hub-blindness is partial: the user gets
   confidentiality but not integrity against a malicious hub.

See [`threat-model.md`](threat-model.md#adversarial-hub-against-chain-integrity)
for the full attack analysis.

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

Every record has **two faces**: a small searchable **metadata
face** (always pulled by browse / list / search) and an optional
larger **body face** (fetched lazily when the user opens the
record). The cumulative-frames snapshot per RecordType carries
metadata inline (when small) or as a DataMap pointer, plus a body
DataMap pointer when the record has a body. This is what lets
clients build a unified search index by pulling metadata only —
no body chunks are downloaded until a user actually opens a
record. See [`data-format.md#recordframe`](data-format.md) for the
byte-level split.

### Writing a record

1. **Plaintext on client.** A record (credential, alias config,
   alias message, …) is built per the per-RecordType schemas in
   [`record-types.md`](record-types.md) — a `{metadata, body}`
   pair where the body is optional.
2. **Seal each face.** Metadata and body are AEAD-sealed
   independently under the per-(user, record_type) key with
   distinct AAD prefixes (`vitonomi/record_metadata/v1`,
   `vitonomi/record_body/v1`) so a ciphertext is cryptographically
   bound to its face and its `record_id`. Argon2id-derived keys
   are unchanged from the master-key path.
3. **Self-encrypt the non-inline faces.** Metadata bytes that
   exceed the inline threshold (and every body) are run through
   upstream `@autonomi/self-encryption` to produce N encrypted
   chunks plus a DataMap. Small metadata is inlined directly into
   the RecordFrame and rides inside the snapshot envelope's AEAD.
4. **Chunks → vault store.** Each chunk is written to the user's
   main vault (and replicated to peer vaults via libp2p). In v1.1,
   chunks also flow to the Autonomi network.
5. **DataMaps → RecordFrame → snapshot → snapshot chain.** The
   RecordFrame carries inline metadata (or a metadata DataMap) and
   the optional body DataMap. It is folded into the per-RecordType
   snapshot under the cumulative-frames model. The snapshot is
   signed, AEAD-encrypted, self-encrypted, and its DataMap is
   carried in a fresh head pointer; the head pointer is
   AEAD-encrypted and PUT to the hub.

### Reading a record

Browsing and searching decrypt **only** the per-RecordType
snapshot, yielding every record's metadata face for that type in a
single pass. The cross-type search index (`core::search::LibraryIndex`)
is built by merging the metadata streams of the loaded RecordTypes —
it never touches body chunks. When the user opens a specific
record, the client fetches that one record's body chunks via the
RecordFrame's `body_data_map` and AEAD-opens it locally.

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
