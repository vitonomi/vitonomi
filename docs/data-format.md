---
formatVersion: 2
status: partial
last-reviewed: 2026-05-12
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
  table + key blob V1 + seed phrase + invite token + admin chain
  entry.
- v0.2 (data-plane slice 1, 2026-05-12): key blob V2 with
  `user_aead_master` + RecordType discriminator + RecordFrame
  (metadata + body split) + Snapshot envelope (3 layers) + Head
  pointer envelope (3 layers) + `backup_targets` enumeration.
- v0.3 (Phase 8): alias-pubkey directory entry.

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

This document grows incrementally. As of mini-MVP Step 2 (with the
Step-2.1 hub-blindness amendment of 2026-05-05) the
**Key blob**, **Seed phrase**, **Cluster shared key + pepper**,
**`user_lookup_id`**, **Invite token**, and **Admin chain entry**
sections below are normative; the rest are still TBD (record-types,
snapshot envelope, head pointer, alias directory) and will land
with their respective implementation phases. The Rust types backing
the normative sections live in `vitonomi-core::crypto::*` and
`vitonomi-core::protocol::wire::*` — those struct definitions are
the source-of-truth byte layouts that this document narrates.

> **Hub-blindness invariant.** Every section below is designed so
> the hub reads only the absolute minimum coordination metadata.
> See [`architecture.md`](architecture.md#hub-blindness-trust-topology)
> for the trust topology. This document is the byte-level
> commitment.

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
  magic:          bytes(4)   = b"VKB2",
  format_version: uint8      = 2,
  enc_salt:       bytes(16+),
  argon2_params:  Argon2Params,
  ciphertext:     bytes(var), // nonce(24) || aead_ct(MasterSecretKeys-CBOR)
}
```

Encoded with deterministic CBOR (RFC 8949 strict). Magic is the
ASCII bytes `0x56 0x4b 0x42 0x32`. V1 was `VKB1` and did not carry
the `user_aead_master` field below; V1 blobs are not readable by
V2 code. Pre-live there is no migration shim.

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

### `MasterSecretKeys` plaintext (V2)

```text
MasterSecretKeys {
  identity:           bytes(32),  // ML-DSA-65 FIPS 204 seed `xi`
  cluster_admin:      bytes(32),  // ML-DSA-65 FIPS 204 seed `xi`
  kem:                bytes(64),  // ML-KEM-768 FIPS 203 seed (d || z)
  cluster_pepper:     bytes(32),  // see "Cluster pepper + lookup_id"
  cluster_shared_key: bytes(32),  // see "Cluster shared key"
  user_aead_master:   bytes(32),  // V2 — see "Per-user AEAD master"
}
```

The seed-only encoding for the keypairs is a deliberate choice:
storing just the FIPS internal seeds (rather than the expanded
signing / decapsulation keys) gives a compact, format-stable
payload that deterministically regenerates the full keypair on
every use. See [`autonomi-compat.md`](autonomi-compat.md) for the
rationale.

`cluster_pepper`, `cluster_shared_key`, and `user_aead_master` are
all HKDF-derived from the BIP-39 seed at registration (info
strings below) and stored in the blob so loss of the hub doesn't
lose them. All three are deterministic, so seed-phrase recovery
rebuilds them.

### Per-user AEAD master

A 32-byte HKDF-SHA-256 output that is the IKM for two further
derivations:

- **Per-(user, record_type) AEAD key** — `HKDF(IKM=user_aead_master,
  salt=user_id, info="vitonomi/record_aead/v1/" || record_type)` —
  seals record payloads and signed snapshot envelopes.
- **Per-user head-pointer AEAD key** — `HKDF(IKM=user_aead_master,
  salt=user_id, info="vitonomi/head_pointer_aead/v1")` — seals the
  user's head-pointer envelope.

Why a separate IKM from `cluster_shared_key`: every cluster member
can derive `cluster_shared_key` (it's the K2 invite-KEK path).
Using it as IKM here would let any cluster member derive any other
member's per-user record AEAD key. `user_aead_master` lives only
in the user's own key blob, never traverses any other channel.

`user_aead_master` is derived as
`HKDF(IKM=BIP-39 seed, salt=None, info="vitonomi/user_aead_master/v1",
out_len=32)`. Deterministic from seed → seed-phrase recovery
rebuilds it without round-tripping the hub.

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

The 64-byte BIP-39 PBKDF2 seed (`mnemonic.to_seed("")`) is the
input to:

- `cluster_pepper = HKDF-SHA-256(seed, info="vitonomi/cluster_pepper/v1", length=32)`
- `cluster_shared_key = HKDF-SHA-256(seed, info="vitonomi/cluster_shared_key/v1", length=32)`

The master keypairs (`identity`, `cluster_admin`, `kem`)
remain random under the mini-MVP design and live in the
AEAD-encrypted key blob; once `ml-dsa` exposes the FIPS 204
internal-seed API on a non-rc release, those will become
deterministic from the BIP-39 seed too.

## Cluster pepper + `user_lookup_id`

`cluster_pepper` is a 32-byte secret used to defeat bulk username
enumeration by a malicious hub. It is HKDF-derived from the BIP-39
seed (see above) and stored ONLY inside the encrypted key blob —
the hub never sees it.

`user_lookup_id` is the hub-side index for a user record. It is
NOT the username:

```text
user_lookup_id =
  argon2id(
    password = utf8_bytes(username) || cluster_pepper,
    salt     = cluster_id,
    m        = 32 * 1024,    // 32 MiB
    t        = 2,
    p        = 1,
    out_len  = 32,
  )
```

Properties:

- The hub stores users keyed by `user_lookup_id` and never sees
  the raw `username` or `cluster_pepper`.
- Bulk enumeration over a hosted-hub-known cluster_id requires
  Argon2id cost per guess AND a 256-bit pepper guess —
  computationally infeasible.
- Cross-cluster correlation (same username on two clusters) is
  broken because each cluster has a different pepper.
- **Residual risk:** a hosted-hub operator who registers as a
  user on a target cluster learns its `cluster_pepper` (it's in
  *their* key blob) and can then test "is `username` registered
  here?" one Argon2 hash at a time. This is a targeted-
  confirmation leak; OPAQUE PAKE in v1.1+ closes it.

## Cluster shared key

`cluster_shared_key` is a 32-byte symmetric key (XChaCha20-Poly1305)
used to AEAD-seal cluster-scoped metadata (vault directory entries,
admin chain payloads, future alias directory entries). It is
HKDF-derived from the BIP-39 seed (see above) so seed-phrase
recovery regenerates it.

Distribution to other cluster members:
- **New vault during accept** — sealed inside the invite's inner
  payload (which is transmitted out-of-band admin → vault
  operator; the hub never sees the inner payload). See "Invite
  token" below.
- **New cluster member** (v1.1+) — sealed via ML-KEM-768 to the
  invitee's identity pubkey at invite issue time.

Rotation on member revocation is v1.1+; reserve `key_epoch: u32`
in every sealed envelope from day one so rotation is non-breaking.

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

## RecordType discriminator

Each record type has a stable u8 byte assignment carried on the
wire (inside snapshot envelopes and in AEAD AAD bindings):

| RecordType    | u8 byte | Status   |
| ------------- | ------- | -------- |
| Credential    | `0x01`  | MVP      |
| Alias         | `0x02`  | MVP      |
| AliasMessage  | `0x03`  | MVP      |
| Photo         | `0x10`  | reserved |
| Note          | `0x20`  | reserved |
| File          | `0x30`  | reserved |
| Other values  |         | reserved — parse-error on read in V1 |

Adding a new MVP-tier record type does not require a `formatVersion`
bump (readers in V1 already reject reserved bytes). Promoting a
reserved byte from "parse-error" to "live" does — readers must
accept the new value.

## RecordFrame

Per-record framing inside a snapshot envelope. A record has **two
faces**: a small searchable **metadata face** (always pulled by
browse / list / search) and an optional larger **body face** (pulled
lazily when the user opens the record). The frame carries the
metadata face either inline (small records — typical for credentials
and aliases) or as a DataMap pointer to a separately-sealed metadata
blob (when metadata exceeds the inline threshold), plus an optional
DataMap for the body.

```text
RecordFrame {
  record_id:            bytes(16),       // random per-record id
  op_tag:               uint8,            // 0x01 = Put, 0x02 = Delete
  metadata:             optional MetadataField,
                                          // present iff op_tag == 0x01
  body_data_map:        optional bytes(var),
                                          // present iff op_tag == 0x01 AND
                                          //   the record has a body face;
                                          //   upstream self_encryption DataMap
                                          //   bytes (bincode-encoded)
  prev_record_version:  uint64,            // strictly monotonic per record_id
}

MetadataField (CBOR-tagged union; exactly one variant):
  Inline { bytes: bytes(var) }            // tag 0x01;
                                          //   deterministic-CBOR plaintext of the
                                          //   per-RecordType metadata schema;
                                          //   length ≤ 512 bytes after encoding
  Blob   { data_map: bytes(var) }         // tag 0x02;
                                          //   self_encryption DataMap pointing
                                          //   to a sealed metadata blob
```

### The two faces

The **metadata face** holds the searchable / browseable fields the
client needs without unlocking the record:

- `Credential`: title, url, username, tags, folder, `has_totp`,
  `updated_at_ms`. **No password, no TOTP secret, no notes.**
- `Alias`: handle, label, domain, `last_used_at`.
- `AliasMessage`: from, subject, date, snippet, `has_attachments`.
- `Photo` (v1.1+): `taken_at`, w, h, `geo?`, tags, thumbnail DataMap.

The **body face** holds the secret / heavy data: credential
password + TOTP secret + notes + custom fields; the photo image
bytes; the email body + attachments. A record without a body face
(e.g. a public alias entry whose fields all fit in metadata) sets
`body_data_map` absent.

Per-RecordType metadata + body schemas live at
`core::types::*Metadata` and `core::types::*Body`. Schema evolution
is per-type — bumping a `Credential` schema does not force a
`Photo` schema bump.

### Inline vs blob metadata

- **Inline metadata** rides directly inside the signed snapshot
  envelope; no separate sealing step. It is protected by the
  snapshot's Layer-2 AEAD (see "Snapshot envelope" below). The
  512-byte CBOR-encoded ceiling keeps cumulative-frame snapshots
  compact: browsing and search become one fetch + one decrypt, no
  per-record blob round-trips.
- **Blob metadata** is for records whose metadata legitimately
  exceeds the inline threshold (photos with EXIF + thumbnail
  references; long email snippets). It is sealed under the
  per-(user, record_type) AEAD key with AAD

  ```text
  b"vitonomi/record_metadata/v1" || user_id(16) || record_type(1) || record_id(16)
  ```

  then self-encrypted; the frame stores the resulting DataMap.

A writer SHOULD prefer inline whenever the encoded metadata fits;
a reader MUST accept either variant on any record.

### Body sealing

The body face is sealed under the per-(user, record_type) AEAD key
with AAD

```text
b"vitonomi/record_body/v1" || user_id(16) || record_type(1) || record_id(16)
```

then self-encrypted; the frame stores the resulting DataMap. Body
and metadata-blob share the same key but their AAD prefixes differ,
so a ciphertext is cryptographically bound to its face and to its
record — a malicious vault cannot substitute one face for another
or cross records.

Why same key + different AAD instead of separate sub-keys: keeps
the key schedule unchanged from the Key blob V2 design and relies
on the AEAD's AAD-binding for face isolation (standard pattern).
Sub-key derivation can be added later without a wire change if the
threat model demands it.

### Cumulative-frames model

Every snapshot carries the latest frame per `record_id` for that
`record_type`. Compaction (truncating old frames into a fresh
genesis snapshot) is a v1.1 follow-up.

## Per-RecordType payload schemas

Each RecordType defines a `<Type>Metadata` and (optional)
`<Type>Body` CBOR schema. The metadata-face bytes are the value
referenced by [`MetadataField::Inline`] (when ≤ 512 B) or the
plaintext sealed into a [`MetadataField::Blob`] (when larger). The
body-face bytes are the plaintext sealed under
[`record_body_aad`] before self-encryption.

### `CredentialMetadata` (RecordType `0x01`, MVP / Phase 6)

```text
CredentialMetadata {
  format_version:  uint8 = 1,
  title:           string,
  url:             optional string,
  username:        optional string,
  tags:            string[],
  folder:          optional string,
  has_totp:        bool,
  created_at_ms:   uint64,
  updated_at_ms:   uint64,
}
```

CBOR-encoded form is the value carried inside the RecordFrame.
Typical inputs (title 64 chars, URL 128, username 64, 4 tags,
folder 32) encode well under the 512 B inline ceiling — verified
by a property test in `core::types::credential::tests`. Larger
metadata (rare for credentials) automatically falls back to the
Blob variant.

**No secret material may be added to this schema**: passwords,
TOTP secrets, notes, and custom fields live on
`CredentialBody`. A regression test
(`metadata_json_keys_contain_no_secret_field_names`) rejects any
field whose lowercase name matches `password|totp|secret|notes|
private_key|passwd|pass`.

### `CredentialBody` (RecordType `0x01`)

```text
CredentialBody {
  format_version:  uint8 = 1,
  password:        SecretString,           // zeroized on drop
  totp:            optional TotpConfig,
  notes:           optional string,
  custom_fields:   (string, SecretString)[],
}

TotpConfig {
  secret:       SecretBytes,               // raw bytes; base32 lives at the import/export edge
  algorithm:    uint8,                     // 0 = SHA1, 1 = SHA256, 2 = SHA512 (CBOR-tagged enum)
  digits:       uint8,                     // RFC 6238: 6, 7, or 8
  period_secs:  uint32,                    // RFC 6238 default: 30
}
```

Sealed under [`record_body_aad`] then self-encrypted; the
RecordFrame stores the resulting DataMap as `body_data_map`.

## Snapshot envelope

Three nested layers — the chain head, the AEAD envelope, and the
self-encryption chunking.

The snapshot envelope protects the **frame list and any inline
metadata**. Blob-metadata and body ciphertexts referenced by
frames are sealed separately (see "RecordFrame" above) and live as
content-addressed chunks in the vault chunk store; the snapshot
only carries their DataMaps. So a single snapshot decrypt yields
every record's searchable face for that RecordType — no per-record
blob fetches are needed to browse or search.

### Layer 1 — `Snapshot` plaintext (signed)

```text
Snapshot {
  format_version: uint8 = 1,
  record_type:    uint8,                // RecordType discriminator
  seq:            uint64,                // monotonic; genesis = 0
  prev_address:   optional bytes(32),    // ChunkAddress of prior snapshot's
                                         //   first chunk; None at genesis
  frames:         RecordFrame[],         // cumulative live frames
  backup_targets: string[],              // {"vault"} in MVP
}
SignedSnapshot {
  snapshot: Snapshot,
  sig_user: bytes(~3309),                // ML-DSA-65 over CBOR(Snapshot)
}
```

Frames inside a snapshot MUST be sorted by `record_id` lexicographically
so deterministic CBOR encoding is stable across equivalent logical
states.

### Layer 2 — AEAD encryption

- Algorithm: **XChaCha20-Poly1305** (algId `0x03`).
- Key: per-(user, record_type) — see "Per-user AEAD master".
- Nonce: 24 random bytes per re-encryption, prefixed.
- AAD: `b"vitonomi/snapshot/v1" || user_id(16) || record_type(1) ||
  seq_be8`. Binds the user, record type, and seq into the seal so a
  malicious hub cannot substitute a snapshot from a different
  `(user, record_type, seq)` triple.
- Plaintext: deterministic-CBOR-encoded `SignedSnapshot`.

### Layer 3 — Self-encryption

- Input: the Layer-2 AEAD ciphertext.
- Output: a `Vec<Chunk>` + a `DataMap`, byte-identical to upstream
  `self_encryption::encrypt(input)` (see
  [`autonomi-compat.md`](autonomi-compat.md)).
- The DataMap rides inline in the head pointer (Layer 1 of the head
  pointer below); chunks land in the vault chunk store under their
  BLAKE3 content addresses.

## Head pointer envelope

Three nested layers — the plaintext head pointer, the AEAD envelope,
and the hub-side outer-signed wrapper.

### Layer 1 — `HeadPointer` plaintext (signed)

```text
HeadPointer {
  format_version:    uint8 = 1,
  snapshot_data_map: bytes(var),      // upstream self_encryption DataMap
                                       //   bytes for the snapshot envelope
  seq:               uint64,
  sig_user_inner:    bytes(~3309),     // ML-DSA-65 over
                                       //   (snapshot_data_map || seq_be8)
}
```

### Layer 2 — AEAD encryption

- Algorithm: **XChaCha20-Poly1305** (algId `0x03`).
- Key: per-user head-pointer key — see "Per-user AEAD master".
- Nonce: 24 random bytes per re-encryption, prefixed.
- AAD: `b"vitonomi/head_pointer/v1" || cluster_id(32) || user_id(16) ||
  record_type(1)`.
- Plaintext: deterministic-CBOR-encoded `HeadPointer`.

### Layer 3 — `StoredHeadPointer` (what the hub stores)

```text
StoredHeadPointer {
  format_version:    uint8 = 1,
  seq:               uint64,           // exposed plaintext — rollback
                                       //   protection key on the hub side
  encrypted_pointer: bytes(var),       // Layer-2 AEAD ciphertext
  sig_user_outer:    bytes(~3309),     // ML-DSA-65 over
                                       //   cluster_id(32) || user_id(16)
                                       //   || record_type(1) || seq_be8
                                       //   || sha256(encrypted_pointer)
}
```

The hub sees: `seq` (plaintext, monotonic), the opaque
`encrypted_pointer`, and `sig_user_outer`. The hub enforces
`new.seq > stored.seq` on `PUT /v1/library/head/...` (Slice 4 of the
data-plane milestone). The outer sig prevents a malicious hub from
substituting a fabricated body — the client verifies it before
opening the AEAD layer.

## Invite token

Admin-signed authorisation for a single vault to join a cluster.
**Two-layered** under hub-blindness: an outer summary the hub
stores for admission gating, and an inner payload (containing
`vault_role`, `hub_url`, `hub_cert_fingerprint`, and the sealed
`cluster_shared_key`) that the admin transmits out-of-band to
the vault operator and the hub NEVER sees.

### Inner payload (CBOR; admin → vault operator only)

```text
InviteInnerPayload {
  format_version:        uint8 = 1,
  vault_role:            string,  // "storage" (closed enum)
  hub_url:               string,
  hub_cert_fingerprint:  string,  // "sha256:<base64url-no-padding>"
                                  //   SPKI hash of hub TLS leaf cert
  sealed_cluster_key:    bytes(72),  // nonce(24) || aead_ct(32 + tag 16)
                                     //   under per-invite KEK (see below)
}
```

The `sealed_cluster_key` is `cluster_shared_key` AEAD-sealed under
a per-invite key-encrypting key (KEK) the admin derives as:

```text
invite_kek = HKDF-SHA-256(
  ikm  = cluster_admin_secret_key_bytes,
  info = "vitonomi/invite_kek/v1",
  salt = invite_nonce,   // 32 bytes
  out_len = 32,
)
```

Only the cluster admin can compute `invite_kek` (it requires the
admin sk). The vault, on accept, receives the full inner payload
and asks the admin (out-of-band, e.g. embedded with the invite)
for the same `invite_kek`, then unseals `cluster_shared_key`
locally. The hub is never part of the key delivery path.

> **K2 (this design) vs K1 (rejected).** K1 would have had the
> admin POST `cluster_shared_key` sealed to each accepted vault's
> pubkey *after* accept, leaving a "ghost vault" admission window
> where the hub knew acceptance occurred but the chain didn't
> reflect it. K2 closes the window: vaults are operational
> immediately at accept; the chain still ratifies lazily but the
> cluster shared key is already in the vault's hands.

### Outer summary (CBOR; what the hub stores)

```text
InviteOuterSummary {
  format_version:      uint8 = 1,
  cluster_id:          bytes(32),
  invite_nonce:        bytes(32),       // single-use; cluster-scoped uniqueness
  expires_at_ms:       uint64,
  inner_payload_hash:  bytes(32),       // sha256 of CBOR-encoded InviteInnerPayload
  sig_cluster_admin:   bytes(~3309),    // ML-DSA-65 over CBOR(everything above)
}
```

Hub admission rules:

1. Verify `sig_cluster_admin` against the stored cluster admin
   pubkey.
2. **Atomically dedup `invite_nonce`** at the SQL layer (`INSERT
   ... ON CONFLICT(invite_nonce) DO NOTHING`); reject any second
   writer.
3. On accept, verify the vault's submission contains an inner
   payload whose sha256 equals `inner_payload_hash` (so a vault
   cannot substitute a different inner).

Strict parse — unknown `format_version`, missing required fields,
or invalid `cluster_id` are all parse errors.

### Vault acceptance signature

When the vault accepts an invite it sends, alongside the outer
summary + inner payload + its public key, its own signature over
`invite_nonce || vault_pubkey_bytes` (simple byte concatenation,
no CBOR). This proves possession of the vault's secret half
before the hub binds the pubkey to the cluster.

## Admin chain entry

Append-only signed log of cluster admin actions. Under
hub-blindness the chain entry is **two-layered**: a plaintext
outer envelope the hub uses for ordering and admission gating,
and an AEAD-sealed inner body containing the action contents.

The chain is replicated to the hub *and* to every vault in the
cluster. **The hub's chain copy is advisory** — only vaults are
trusted to serve the canonical chain. See
[`threat-model.md`](threat-model.md#adversarial-hub-against-chain-integrity)
for the attack analysis and
[`architecture.md`](architecture.md#chain-integrity-is-a-vault-property-not-a-hub-property)
for the mitigations.

### Outer envelope (CBOR; what the hub stores)

```text
AdminChainEntryOuter {
  format_version:      uint8 = 1,
  cluster_id:          bytes(32),
  prev_hash:           bytes(32),       // sha256 of previous outer; zero32 for genesis
  seq:                 uint64,          // 0 for genesis, monotonic +1
  admin_pubkey_epoch:  uint32 = 0,      // reserved for admin-key rotation (v1.1+)
  key_epoch:           uint32 = 0,      // reserved for cluster_shared_key rotation (v1.1+)
  sealed_inner:        bytes(var),      // nonce(24) || aead_ct(CBOR(InnerBody) + tag 16)
                                        //   AEAD-sealed under cluster_shared_key
                                        //   AAD = cluster_id || seq_be8 || prev_hash
  sig_admin_outer:     bytes(~3309),    // ML-DSA-65 over CBOR of all fields above
}
```

The hub verifies `sig_admin_outer` against the cluster admin
pubkey to gate admission (no forged entries) and enforces
seq+prev_hash continuity (no out-of-order writes). The hub does
NOT — and cannot — read `sealed_inner`.

### Inner body (CBOR; sealed; only cluster members read this)

```text
AdminChainEntryInner {
  format_version:  uint8 = 1,
  action:          string,    // "cluster-init" | "vault-enroll" | "vault-revoke" | "user-invite" | "user-revoke"
  payload:         bytes(var), // CBOR, action-specific
  sig_admin_inner: bytes(~3309), // ML-DSA-65 over (action || payload)
                                 //   defends against an admin-key holder reusing
                                 //   sealed_inner content from a different chain position
}
```

Why a second admin signature inside? Because `sig_admin_outer`
covers the sealed bytes (which the admin produces) but not the
*content* directly. `sig_admin_inner` lets a vault verify "this
content was admin-authorised" without depending on the AEAD
sealing for authenticity (defense-in-depth: if a future revision
of this format changes the sealing, the inner sig is still a
content-only attestation).

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
- `action == "cluster-init"` (after unsealing)
- `admin_pubkey_epoch == 0`
- `key_epoch == 0`

A chain whose seq-0 entry violates any of these MUST be rejected.

### Hash linking

For every entry `n+1`, `prev_hash` is computed as
`sha256(CBOR-encode(outer_envelope_n))` — that is, the SHA-256 of
the fully-CBOR-encoded *outer* envelope including
`sig_admin_outer`, NOT the unsealed inner. This binds each entry
to its predecessor while still allowing the hub to compute and
verify `prev_hash` without ever decrypting `sealed_inner`.

### Verification (vault side)

`verify_chain(admin_pk, cluster_shared_key, cluster_id, &outers)` runs:
1. Reject empty chains.
2. For each outer envelope in order:
   - `outer.cluster_id == cluster_id`.
   - `outer.seq == i` (0-based).
   - `outer.prev_hash == expected_prev` (zero32 for `i = 0`,
     `sha256(CBOR(outers[i-1]))` otherwise).
   - `verify_outer(admin_pk, outer)` succeeds.
   - AEAD-open `outer.sealed_inner` with `cluster_shared_key`
     and AAD = `cluster_id || seq_be8 || prev_hash`.
   - Verify `inner.sig_admin_inner` against `admin_pk`.
   - For `i = 0`: `inner.action == "cluster-init"`.
3. Set `expected_prev = sha256(CBOR(outer))` and continue.

### Pending acceptance (hub-side, NOT a chain entry)

When a vault accepts an invite under K2, the hub records a
**pending acceptance** alongside the vault directory:

```text
PendingAcceptance {
  acceptance_id:           string,         // opaque random
  vault_id:                bytes(16),
  vault_pubkey:            bytes(~1952),   // ML-DSA-65 (plaintext, needed for WS auth)
  invite_nonce:            bytes(32),
  sealed_acceptance_meta:  bytes(var),     // AEAD-sealed under invite_kek
                                           //   { vault_name, accept_ts_ms, vault_role }
  created_at_ms:           uint64,
  expires_at_ms:           uint64,         // created_at_ms + 7 days (TTL)
}
```

Pending acceptances are NOT chain entries. The vault is operational
(K2 already delivered the cluster shared key) but does not appear
in the formal admin chain. On the admin's next login, the CLI
fetches pending acceptances, verifies each, signs proper
`vault-enroll` chain entries, and posts them via
`POST /v1/admin-chain/{cluster_id}`. After ratification the
pending row is purged. Pending acceptances older than 7 days are
purged unconditionally; the corresponding vault must be
re-invited.

`sealed_acceptance_meta` uses the per-invite KEK so even the
pending row leaks no metadata to the hub beyond the irreducible
plaintext fields (`vault_pubkey`, `invite_nonce`, timestamps).

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
| RecordFrame            | `vectors/record-frame/` | TBD (Phase 5) — includes Inline and Blob metadata variants |
| Snapshot envelope      | `vectors/snapshot/`     | TBD (Phase 5)                         |
| Head pointer           | `vectors/head-pointer/` | TBD (Phase 5)                         |
| Record metadata blob   | `vectors/record-metadata/` | TBD (Phase 5) — Blob-variant sealing round-trip |
| Record body            | `vectors/record-body/`  | TBD (Phase 5) — body sealing round-trip |
| Alias-pubkey directory | `vectors/alias-pubkey/` | TBD (Phase 8)                         |
