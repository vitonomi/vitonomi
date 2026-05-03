---
formatVersion: 1
status: partial
last-reviewed: 2026-05-01
---

# vitonomi data format

This document specifies every byte that vitonomi persists or
transmits in a vitonomi-defined format. Bytes are normative: the
exact layout described here is what implementations MUST produce
and consume.

For chunk and DataMap formats, vitonomi delegates to the upstream
Autonomi 2.0 specification; see
[`autonomi-compat.md`](autonomi-compat.md) for the version pin and
conformance vector identifiers.

**Status: partial.** This document grows incrementally across
implementation phases:

- v0.1 (Phase 2 → mini-MVP Step 2): conventions + algorithm-id
  table + key blob + seed phrase + invite token + admin chain
  entry
- v0.2 (Phase 5): snapshot envelope + RecordFrame + head pointer
- v0.3 (Phase 8): alias-pubkey directory entry

Sections marked **TBD** are landing in the corresponding phase.

## Conventions

These rules apply to every byte layout in this document.

- **Endianness.** All multi-byte integers are little-endian.
- **Length-prefix encoding.** Variable-length fields are preceded by
  a `varint` length (LEB128, à la protobuf). The maximum varint is
  10 bytes.
- **Enum encoding.** All enum values are encoded as `uint8`
  discriminators. Reserved ranges are documented per enum.
- **Optional fields.** Optional fields are preceded by a `uint8`
  presence bit (`0x00` = absent, `0x01` = present, anything else =
  parse error).
- **Reserved fields.** Bytes labelled "reserved" MUST be zero on
  write and MUST be rejected on read if non-zero (forward
  compatibility lever; future versions can use these bytes via a
  format-version bump).
- **Magic numbers.** Each top-level envelope starts with a 4-byte
  ASCII magic. Implementations MUST verify the magic before any
  further parsing.
- **Strings.** UTF-8, NFC-normalised, length-prefixed by varint.
  Strings MUST NOT contain NUL bytes; parsers reject if so.
- **Hashes.** All hashes are byte arrays of fixed length; the
  algorithm is identified by the surrounding context's `algId`
  field, never inferred.
- **Versioning.** Every top-level envelope carries a `formatVersion:
uint8` immediately after the magic. Same-version readers MUST
  accept; different-version readers fail with a typed error and a
  human-readable migration message.

## Algorithm identifiers

Whenever an envelope refers to a cryptographic primitive, it does so
via this `algId: uint8` table. New entries land in this table before
the corresponding crypto wrapper ships.

| algId         | Primitive             | Used for                    |
| ------------- | --------------------- | --------------------------- |
| `0x01`        | ML-DSA-65             | Asymmetric signatures       |
| `0x02`        | ML-KEM-768            | Key encapsulation           |
| `0x03`        | XChaCha20-Poly1305    | AEAD                        |
| `0x04`        | Argon2id              | Password KDF                |
| `0x05`        | HKDF-SHA-256          | Sub-key derivation          |
| `0x06`        | SHA-256               | Hashing (general)           |
| `0x07`        | BLAKE3                | Chunk addressing (Autonomi) |
| `0x08`        | CBOR (RFC 8949, det.) | Record-plaintext encoding   |
| `0x09`–`0x0f` | reserved              | future primitives           |

Anything outside this table is a parse error. New algorithms get a
new entry and a `formatVersion` bump on every envelope that uses
them.

## Mini-MVP scope

This document grows incrementally. As of mini-MVP Step 2 the
**Key blob**, **Seed phrase**, **Invite token**, and **Admin
chain entry** sections below are normative; the rest are still
TBD (record-types, snapshot envelope, head pointer, alias
directory) and will land with their respective implementation
phases. The Rust types backing the normative sections live in
`vitonomi-core::crypto::*` and `vitonomi-core::protocol::wire::*`
— those struct definitions are the source-of-truth byte layouts
that this document narrates.

## Key blob

The user's master keypair AEAD-encrypted under the encryption
key derived from password via Argon2id. Stored on the hub
(`/v1/keyblob`), in IndexedDB on browsers, in
`$XDG_CONFIG_HOME/vitonomi/state.json` for the CLI, and on the
seed-phrase backup file. Multi-tier replication is the recovery
mechanism — see [`architecture.md`](architecture.md).

### Outer envelope (CBOR)

```text
KeyBlob {
  magic:         bytes(4)   = b"VKB1",
  format_version: uint8      = 1,
  ciphertext:    bytes(var), // nonce(24) || aead_ct
}
```

Encoded with deterministic CBOR (RFC 8949 strict). Magic is the
ASCII bytes `0x56 0x4b 0x42 0x31`.

### AEAD layer

- Algorithm: **XChaCha20-Poly1305** (algId `0x03`).
- Key: 32-byte AEAD key, output of `Argon2id(password, enc_salt,
  argon2_params)` (see "Argon2id" below).
- Nonce: 24 random bytes per re-encryption, prefixed to the AEAD
  output (so `ciphertext = nonce(24) || ct(var) || tag(16)`).
- Associated data (AAD): the 5 bytes
  `magic(4) || format_version(1)`. Tampering with either field
  invalidates the AEAD tag.
- Plaintext: deterministic-CBOR-encoded `MasterSecretKeys` struct
  (see below).

### `MasterSecretKeys` plaintext

```text
MasterSecretKeys {
  identity:      bytes(32),  // ML-DSA-65 FIPS 204 seed `xi`
  cluster_admin: bytes(32),  // ML-DSA-65 FIPS 204 seed `xi`
  kem:           bytes(64),  // ML-KEM-768 FIPS 203 seed (d || z)
}
```

The seed-only encoding is a deliberate choice: storing just the
FIPS internal seeds (rather than the expanded signing /
decapsulation keys) gives a compact, format-stable payload that
deterministically regenerates the full keypair on every use.
See [`autonomi-compat.md`](autonomi-compat.md) for the rationale.

### Argon2id parameter encoding

Argon2id parameters travel separately from the key blob (in
`/v1/auth/login/start` responses and in the cluster registration
payload):

```text
Argon2Params {
  mem_kib:     uint32,  // KiB; production ≥ 256 * 1024
  time_cost:   uint32,  // production ≥ 3
  parallelism: uint32,  // production ≥ 1
  out_len:     uint32,  // always 32 in this version
}
```

Production minimum: `mem_kib >= 256 * 1024 && time_cost >= 3 &&
parallelism >= 1`. The `core` crate's `test-crypto` feature swaps
in a fast `m=8 MiB / t=1` profile for tests; production builds
must NOT have the feature enabled.

## Seed phrase

BIP-39 wordlist (English; other languages v1.1+). **24-word
default.** Entropy is a 32-byte random value; checksum +
encoding produced by the upstream `bip39` crate.

The 64-byte BIP-39 PBKDF2 seed (`mnemonic.to_seed("")`) is
**reserved** as the input to a future deterministic
seed → master-key derivation; until `ml-dsa` exposes the
FIPS 204 internal-seed API on a non-rc release, master keys are
random and live solely in the AEAD-encrypted key blob.

## Chunk format

**Delegated to upstream.** Vitonomi chunks are byte-identical to
chunks produced by the pinned `@autonomi/self-encryption` version.
See [`autonomi-compat.md`](autonomi-compat.md) for the version pin,
the chunk-address hash function (BLAKE3 per upstream), the on-disk
shard layout convention, and the upstream conformance vectors that
vitonomi's CI runs as a release gate.

Vitonomi MUST NOT define a chunk format of its own. If the upstream
library bumps its format, the migration is an explicit
`autonomi-compat.md` PR (not a silent dependency upgrade).

## DataMap format

**Delegated to upstream.** Same treatment as chunks. The DataMap
returned by upstream `selfencrypt.encrypt(bytes)` is the format
vitonomi RecordFrames embed and the format the head pointer carries.

## RecordFrame — TBD (Phase 5)

Per-record framing inside a snapshot envelope. Carries the DataMap
for the record's encrypted payload and metadata about the operation
(`put` vs `delete`, `prevRecordVersion`).

## Snapshot envelope — TBD (Phase 5)

Top-level envelope containing a batch of RecordFrames, signed with
ML-DSA-65, then AEAD-encrypted, then run through self-encryption.

## Head pointer envelope — TBD (Phase 5)

Compact envelope holding the latest snapshot's DataMap, seq, and
signature. AEAD-encrypted with the user's encryption key for
storage on the hub, in IndexedDB, and in the seed-phrase backup
file.

## Invite token

Admin-signed authorisation for a single vault to join a cluster.
The CLI builds it locally; the hub stores it for TTL tracking
and replay defense.

### Outer envelope (CBOR)

```text
InviteToken {
  body:              InviteTokenBody,
  sig_cluster_admin: bytes(~3309),  // ML-DSA-65 over CBOR(body)
}
```

### Body

```text
InviteTokenBody {
  format_version:        uint8 = 1,
  cluster_id:            bytes(32),
  vault_role:            string,  // "storage" (closed enum)
  hub_url:               string,
  hub_cert_fingerprint:  string,  // "sha256:<base64url-no-padding>"
                                  //   SPKI hash of hub TLS leaf cert
  invite_nonce:          bytes(32),  // single-use; cluster-scoped uniqueness
  expires_at_ms:         uint64,     // UNIX millis
}
```

Strict parse — unknown `vault_role` values, malformed
`hub_cert_fingerprint` patterns, and missing required fields are
all parse errors. The `format_version` MUST equal the reader's
expected version.

### Acceptance signature

When the vault accepts an invite it sends, alongside the invite,
its own signature over `invite_nonce || vault_pubkey_bytes`
(simple byte concatenation, no CBOR). This proves possession of
the vault's secret half before the hub binds the pubkey to the
cluster.

## Admin chain entry

Append-only signed log of cluster admin actions, replicated to
the hub *and* to every vault in the cluster. The chain is the
mechanism by which cluster identity (membership, revocations,
admin pubkey) survives hub failover.

### Wire format (CBOR)

```text
AdminChainEntry {
  format_version: uint8 = 1,
  cluster_id:     bytes(32),
  prev_hash:      bytes(32),  // sha256 of previous CBOR-encoded entry; zero32 for genesis
  seq:            uint64,     // 0 for genesis, monotonic +1
  action:         string,     // "cluster-init" | "vault-enroll" | "vault-revoke" | "user-invite" | "user-revoke"
  payload:        bytes(var), // CBOR, action-specific
  sig:            bytes(~3309), // ML-DSA-65 over CBOR(EntryBody)
}
```

`EntryBody` (input to `sig`) is everything except `sig` itself,
serialised in the same order:

```text
EntryBody {
  format_version: uint8,
  cluster_id:     bytes(32),
  prev_hash:      bytes(32),
  seq:            uint64,
  action:         string,
  payload:        bytes(var),
}
```

### Action enum

| Value           | Emitted in mini-MVP | Payload schema                                    |
| --------------- | ------------------- | ------------------------------------------------- |
| `cluster-init`  | yes (genesis)       | Free-form bytes; future versions may carry policy |
| `vault-enroll`  | yes                 | Vault metadata (id, name, pubkey-binding details) |
| `vault-revoke`  | reserved            | TBD                                               |
| `user-invite`   | reserved            | TBD                                               |
| `user-revoke`   | reserved            | TBD                                               |

Closed enum — readers reject unknown values with a typed error.

### Genesis invariants

- `seq == 0`
- `prev_hash == zero32` (32 bytes of `0x00`)
- `action == "cluster-init"`

A chain whose seq-0 entry violates any of these MUST be rejected.

### Hash linking

For every entry `n+1`, `prev_hash` is computed as
`sha256(CBOR-encode(entry_n))` — that is, the SHA-256 of the
fully-CBOR-encoded entry including its signature, NOT just the
signing body. This binds each entry not only to its predecessor's
contents but also to the predecessor's signature (so a bit-flip
in any prior signature breaks the chain at that point and every
subsequent entry).

### Verification

`verify_chain(admin_pk, cluster_id, &entries)` runs:
1. Reject empty chains.
2. For each entry in order:
   - `entry.cluster_id == cluster_id`.
   - `entry.seq == i` (where `i` is the index, 0-based).
   - `entry.prev_hash == expected_prev` (zero32 for `i = 0`,
     `sha256(CBOR(entries[i-1]))` otherwise).
   - For `i = 0`: `entry.action == "cluster-init"`.
   - `verify_entry(admin_pk, entry)` succeeds.
3. Set `expected_prev = sha256(CBOR(entry))` and continue.

## Alias-pubkey directory entry — TBD (Phase 8)

Public-readable entry binding `<handle>@<domain>` to an
ML-KEM-768 pubkey, signed by the alias owner's ML-DSA-65 key.

## `backup_targets` enumeration

A typed list embedded in every snapshot envelope. Indicates where
the chunks for this snapshot are deployed.

| Value        | Meaning                                                |
| ------------ | ------------------------------------------------------ |
| `'vault'`    | Replicated to vitonomi vaults (always present in MVP). |
| `'autonomi'` | Replicated to the Autonomi network (post-v1.1).        |

Strict parse: any other value is a parse error. Future tiers add
new enum entries and require a `formatVersion` bump.

## Versioning policy

`formatVersion: uint8` is mandatory in every top-level envelope.

- A reader at version N MUST accept a same-version envelope.
- A reader at version N MUST reject a different-version envelope
  with an explicit error containing the encountered version, the
  reader's version, and a pointer to the migration guide.
- A bump from N to N+1 requires a "Migration from vN" section near
  the top of this document, and an entry in
  [`README.md`](README.md)'s compatibility matrix.

Once a record is written at version N, every subsequent vitonomi
release that supports version N MUST be able to read it. Old data
NEVER becomes unreadable due to a vitonomi upgrade.

## Test vectors

Every byte-format-defining section in this document references
files in `docs/vectors/`. Implementations MUST round-trip every
vector. CI runs the round-trip on every commit.

| Section                | Vector path             | Status                                |
| ---------------------- | ----------------------- | ------------------------------------- |
| Key blob               | `vectors/key-blob/`     | TBD (will land with hub binary, Step 3) |
| Seed phrase            | `vectors/seed-phrase/`  | TBD (will land with hub binary, Step 3) |
| Invite token           | `vectors/invite/`       | TBD (will land with hub binary, Step 3) |
| Admin chain entry      | `vectors/admin-chain/`  | TBD (will land with hub binary, Step 3) |
| Chunk format           | `vectors/chunk/`        | Delegated to upstream                 |
| DataMap                | `vectors/data-map/`     | Delegated to upstream                 |
| RecordFrame            | `vectors/record-frame/` | TBD (Phase 5)                         |
| Snapshot envelope      | `vectors/snapshot/`     | TBD (Phase 5)                         |
| Head pointer           | `vectors/head-pointer/` | TBD (Phase 5)                         |
| Alias-pubkey directory | `vectors/alias-pubkey/` | TBD (Phase 8)                         |
