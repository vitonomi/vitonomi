---
formatVersion: 1
status: stub
last-reviewed: 2026-05-01
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
   pinned upstream library version (see "Version pin" below).
   **Forking is forbidden.** If the upstream library has a bug, we
   fix it upstream.
5. **The vault chunk store IS an Autonomi-format object store.**
   Just running on a single host. Same content addresses, same
   byte layout. The only difference between "stored on a vitonomi
   vault" and "stored on the Autonomi network" is network transport.

These commitments together mean that pushing chunks from a
vitonomi vault to the Autonomi network in v1.1 is the literal
operation `for chunk in store: autonomi.put(chunk.address,
chunk.bytes)`. Zero re-encryption. Zero format conversion.

## Version pin

**TBD (Phase 2).** When the Phase 2 self-encryption wrapper is
written, this section is filled in with:

- Upstream package name and version
- Integrity digest (SHA-256 of the published artefact)
- Link to the upstream release tag
- Link to the upstream specification document

Until Phase 2, this section is a placeholder. The wrapper is not
written, the version is not pinned, and the conformance gate is
not in place. Implementations MUST NOT ship without this section
filled in.

## Hash function for chunk addressing

**TBD (Phase 2).** Whatever upstream specifies — most likely
BLAKE3. Documented authoritatively here once pinned.

## Conformance vectors

**TBD (Phase 2).** Identifiers (paths or hashes) of the upstream
test vectors that vitonomi's CI runs as a release gate. Any
attempt to upgrade the upstream pin re-runs all vectors before
the upgrade can land.

## The bridging interface

`core/src/protocol/AutonomiBridge.ts` is the typed seam between
vitonomi's storage layer and the Autonomi network. Its interface
is:

```typescript
interface AutonomiBridge {
  pushChunks(addresses: ChunkAddress[]): Promise<void>;
  fetchChunk(address: ChunkAddress): Promise<Uint8Array>;
}
```

In MVP, this interface has a no-op in-memory implementation. In
v1.1, it is wired to a real `@autonomi/client`. The interface
shape is locked at Phase 1; the implementation is the v1.1 work.

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
