---
formatVersion: 1
status: partial
last-reviewed: 2026-05-12
---

# Autonomi 2.0 compatibility

vitonomi commits to byte-for-byte compatibility with the Autonomi
2.0 chunk and DataMap formats from day one. This document is the
single source of truth for that commitment. Other specs reference
this document rather than restate.

## Scope of the compatibility commitment

Five concrete, non-negotiable commitments:

1. **Chunk format is Autonomi's chunk format.** A chunk's encrypted
   bytes match exactly what the upstream `@autonomi/self-encryption`
   library produces — same chunking algorithm, same per-chunk key
   derivation, same encryption scheme.
2. **Chunk addressing is Autonomi's addressing.** A chunk's address
   is the hash of its encrypted bytes using Autonomi's hash function.
   A chunk computed locally has the same address it would have on
   the Autonomi network.
3. **DataMap format is Autonomi's DataMap format.** A DataMap
   produced by vitonomi can be handed to any Autonomi-aware client
   and used to fetch and decrypt the original data with no
   transformation.
4. **Self-encryption library is upstream Autonomi code.** vitonomi
   does not implement self-encryption itself. We depend on the
   pinned upstream Rust crate `self_encryption` (see "Version pin"
   below). Because both projects are Rust, integration is direct —
   no JS port to maintain. **Forking is forbidden.** If the upstream
   crate has a bug, we fix it upstream.
5. **The vault chunk store IS an Autonomi-format object store.**
   Just running on a single host. Same content addresses, same
   byte layout. The only difference between "stored on a vitonomi
   vault" and "stored on the Autonomi network" is network transport.

These commitments together mean that pushing chunks from a
vitonomi vault to the Autonomi network in v1.1 is the literal
operation `for chunk in store: autonomi.put(chunk.address,
chunk.bytes)`. Zero re-encryption. Zero format conversion.

## Version pin

| Field            | Value                                                                |
| ---------------- | -------------------------------------------------------------------- |
| Upstream crate   | `self_encryption`                                                    |
| Pinned version   | `=0.35.0` (exact)                                                    |
| Published        | 2026-03-13                                                           |
| License          | GPL-3.0 (allowed by `deny.toml`; AGPL-3.0 absorbs GPL-3.0 cleanly)   |
| Crates.io        | https://crates.io/crates/self_encryption/0.35.0                      |
| Source repo      | https://github.com/maidsafe/self_encryption                          |

Pinned with the `=` operator in `core/Cargo.toml` so a version bump
cannot land silently — any change forces an explicit PR that
re-runs the conformance suite.

The crate's public API surface that vitonomi consumes:

- `pub fn encrypt(bytes: bytes::Bytes) -> Result<(DataMap, Vec<EncryptedChunk>)>`
- `pub fn decrypt(data_map: &DataMap, chunks: &[EncryptedChunk]) -> Result<bytes::Bytes>`
- `pub struct DataMap { chunk_identifiers: Vec<ChunkInfo>, child: Option<usize> }`
- `pub struct ChunkInfo { index: usize, dst_hash: XorName, src_hash: XorName, src_size: usize }`
- `pub struct EncryptedChunk { content: bytes::Bytes }`
- `pub use xor_name::XorName;`     // 32-byte BLAKE3 wrapper

vitonomi wraps these in
[`core/src/crypto/selfencrypt.rs`](../core/src/crypto/selfencrypt.rs)
which exposes `encrypt(&[u8])` and `decrypt(&DataMap, fetcher)` to
the rest of the codebase. Downstream crates never reference upstream
types directly.

## Hash function for chunk addressing

**BLAKE3-256.** The 32-byte `XorName` produced by upstream is
`blake3(encrypted_chunk_bytes).as_bytes()`. vitonomi's
`ChunkAddress` is the same 32 bytes, and the
`verify_chunk_address(address, bytes)` helper in
`crypto::selfencrypt` performs the defence-in-depth check
`blake3(bytes) == address` at every vault storage write.

## Conformance vectors

In-tree round-trip tests live in
`core/src/crypto/selfencrypt.rs::tests`. The critical ones:

- `chunk_address_equals_blake3_of_bytes` — proves the address-
  invariant for inputs of 8 KiB.
- `verify_chunk_address_accepts_match` / `_rejects_tampered_bytes`
  — proves the BLAKE3 verification step.
- `aead_then_selfencrypt_breaks_convergence` — same plaintext
  through two AEAD keys yields disjoint chunk address sets.
- `encrypt_decrypt_round_trip_3kib` / `_100kib` — full pipeline.

A future cross-version conformance suite (slice 3) will compare
vitonomi's chunk bytes byte-for-byte with a side-by-side direct call
into upstream `self_encryption::encrypt(...)` on the same input —
guarding against any wrapper-induced drift.

## The bridging interface

`core/src/protocol/autonomi_bridge.rs` is the typed seam between
vitonomi's storage layer and the Autonomi network. Its trait is:

```rust
#[async_trait]
pub trait AutonomiBridge: Send + Sync {
    async fn push_chunks(&self, addresses: &[ChunkAddress]) -> Result<()>;
    async fn fetch_chunk(&self, address: &ChunkAddress) -> Result<Bytes>;
}
```

In MVP, this trait has a no-op in-memory implementation. In v1.1,
it is wired to the real upstream `autonomi` crate. The trait
signature is locked at Phase 1; the implementation is the v1.1 work.

## What is NOT compatible

Vitonomi-specific envelopes are NOT Autonomi-format. These are
defined by vitonomi and require a vitonomi-aware client to
interpret:

- Snapshot envelopes
- RecordFrames
- Head pointer envelopes
- Admin chain entries
- Key blobs
- Alias-pubkey directory entries
- Per-record-type plaintexts (`CredentialRecord`, `AliasRecord`,
  `AliasMessage`, `CustomDomainRecord`)

Compatibility is at the **chunk and DataMap layer**, not the
application layer. An Autonomi-aware client without vitonomi
knowledge cannot decrypt a vitonomi user's content even if it can
fetch the chunks. That's by design — the bytes are universal; the
meaning is vitonomi-specific.

## AEAD-then-self-encrypt rationale

Vitonomi wraps user plaintext in AEAD (XChaCha20-Poly1305 with a
user-specific key + random nonce) **before** running it through
self-encryption. This breaks self-encryption's convergent property:
same plaintext + different users → different AEAD ciphertexts →
different chunks → different addresses.

Why this layering and not the other way:

- **Convergent encryption alone exposes confirmation-of-file
  attacks.** An adversary who suspects a user holds plaintext X can
  compute X's chunks deterministically and check for those
  addresses in the user's storage.
- **AEAD-then-SE eliminates that risk** because chunks are
  user-specific.
- **Storage cost is negligible.** Self-encryption pads small
  inputs to ≥3 chunks (~9 KB minimum). For credentials and email
  messages, this overhead doesn't matter. For photos in v1.1, the
  ratio of overhead to content shrinks to noise.

The trade-off is **no global storage dedup**. We accept that
trade-off for privacy. See
[`threat-model.md`](threat-model.md#confirmation-of-file-attacks)
for the security analysis.

## Migration scenarios

What happens if upstream `@autonomi/self-encryption` changes its
byte format in a breaking way?

- The version is pinned, so accidental upgrades cannot happen.
- An explicit migration PR is required. The PR must:
  1. Update the pin in this document.
  2. Update the conformance vector references.
  3. Document a migration path for existing users (if the change
     is not backward-compatible).
  4. Bump the relevant `formatVersion` in
     [`data-format.md`](data-format.md).
- vitonomi may choose to remain on an older upstream major if a
  bump breaks compatibility in ways we cannot migrate cleanly.

## Cross-references

- [`data-format.md`](data-format.md) — defers chunk and DataMap
  layouts to upstream via this document.
- [`encryption-flows.md`](encryption-flows.md) — uses self-
  encryption at the storage step of every write flow.
- [`architecture.md`](architecture.md) — places this document in
  the broader system context.
- [`threat-model.md`](threat-model.md) — confirmation-of-file
  defence rationale.
