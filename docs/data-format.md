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

- v0.1 (Phase 2): conventions + algorithm-id table + key blob + seed phrase
- v0.2 (Phase 5): snapshot envelope + RecordFrame + head pointer
- v0.3 (Phase 8): alias-pubkey directory entry
- v0.4 (Phase 9): admin chain entries

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

## Key blob — TBD (Phase 2)

Format of the user's master keypair AEAD-encrypted under the
encryption key derived from password via Argon2id. Sized for
ML-DSA-65 + ML-KEM-768 secret bytes plus padding.

## Seed phrase — TBD (Phase 2)

BIP-39 wordlist (English; other languages v1.1+). 24-word default.
Entropy round-trip and seed-derived deterministic keypair tests.

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

## Admin chain entry — TBD (Phase 9)

Per-cluster signed log of admin actions (invite, revoke, set quota,
add/revoke vault, rotate admin key).

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

| Section                | Vector path             | Status                |
| ---------------------- | ----------------------- | --------------------- |
| Key blob               | `vectors/key-blob/`     | TBD (Phase 2)         |
| Seed phrase            | `vectors/seed-phrase/`  | TBD (Phase 2)         |
| Chunk format           | `vectors/chunk/`        | Delegated to upstream |
| DataMap                | `vectors/data-map/`     | Delegated to upstream |
| RecordFrame            | `vectors/record-frame/` | TBD (Phase 5)         |
| Snapshot envelope      | `vectors/snapshot/`     | TBD (Phase 5)         |
| Head pointer           | `vectors/head-pointer/` | TBD (Phase 5)         |
| Admin chain entry      | `vectors/admin-chain/`  | TBD (Phase 9)         |
| Alias-pubkey directory | `vectors/alias-pubkey/` | TBD (Phase 8)         |
