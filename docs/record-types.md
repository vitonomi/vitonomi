---
formatVersion: 1
status: partial
last-reviewed: 2026-05-15
---

# Record-type schemas

**Status: stub.** Per-RecordType schemas are filled in by their
delivering phase (Phase 6 for credentials, Phase 7 for aliases +
alias-messages + custom domains, v1.1+ for photos / notes / files).
See [README.md](README.md) for the suite reading order and the
phase-mapping table for what lands when.

## Convention: every record is a (metadata, body) pair

Every RecordType is defined as a pair of CBOR schemas:

- `<Type>Metadata` — the small **searchable / browseable face**.
  Inline in the RecordFrame whenever the encoded CBOR is ≤ 512 B.
  Carries no secret material. Drives `list_metadata`, the
  cross-type `core::search::LibraryIndex`, and every UI surface
  that does not require unlocking the record.
- `<Type>Body` — the optional **secret / heavy face**. Sealed as
  a separate body blob and fetched lazily when the user opens the
  record. RecordTypes whose entire content fits in the metadata
  face may omit `<Type>Body` entirely; the RecordFrame's
  `body_data_map` is then absent.

This split is the contract that lets clients build a unified
search index without ever fetching body chunks, and is what makes
the data format viable for both small types (credentials, aliases)
and large types (photos, files in v1.1+). The byte-level framing
is specified in [data-format.md#recordframe](data-format.md).

## Per-RecordType schemas

### `Credential` (Phase 6, shipped)

| Face       | Rust type                                       | Contains                                                              |
| ---------- | ----------------------------------------------- | --------------------------------------------------------------------- |
| Metadata   | `vitonomi_core::types::credential::CredentialMetadata` | title, url, username, tags, folder, has_totp, created/updated timestamps |
| Body       | `vitonomi_core::types::credential::CredentialBody`     | password, optional TOTP entry, notes, custom_fields (all secret)      |

Byte layout pinned in
[`data-format.md`](data-format.md#per-recordtype-payload-schemas).

The metadata schema explicitly excludes secret fields — a unit
test rejects any future field whose name matches `password |
totp | secret | notes | private_key | passwd | pass`. Anything
secret belongs on `CredentialBody`.

### `Alias` (Phase 7, shipped)

| Face     | Rust type                                          | Contains                                                                                              |
| -------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Metadata | `vitonomi_core::types::alias::AliasMetadata`        | alias_handle, namespace, label, alias_kem_pubkey, sig_user, expiry, active, spam_policy, tags, created |
| Body     | `vitonomi_core::types::alias::AliasBody`            | alias_kem_secret_key (ML-KEM-768 seed, ZeroizeOnDrop)                                                 |

Byte layout in
[`data-format.md`](data-format.md#aliasmetadata). The
`sig_user_over_pubkey` binds the KEM pubkey to
`(alias_handle, namespace)` so a fetcher can detect hub-side
substitution.

### `AliasMessage` (Phase 7, shipped)

| Face     | Rust type                                                  | Contains                                                              |
| -------- | ---------------------------------------------------------- | --------------------------------------------------------------------- |
| Metadata | `vitonomi_core::types::alias_message::AliasMessageMetadata` | alias_id, sender, subject, snippet (≤140), spf/dkim/dmarc, attachments |
| Body     | (raw bytes, no Rust struct)                                 | encrypted MIME bytes — the message itself                             |

The body face IS the message content; there is no separate
`*Body` Rust struct. The RecordFrame's `body_data_map` points
at the chunks.

### `Domain` (Phase 7, shipped)

Unified record for both subdomain claims under hub-managed
bases AND user-owned BYO domains verified via DNS challenge.

| Face     | Rust type                                  | Contains                                                                                                |
| -------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| Metadata | `vitonomi_core::types::domain::DomainMetadata` | domain (full), is_custom, status, verified_at, optional challenge (custom only), optional base_domain (subdomain only), created |

No body face — the record fits entirely in metadata.
Discrimination at the field level via `is_custom`:

- `is_custom = false`, `base_domain = Some(<base>)`, `status =
  Active` immediately on claim — these are subdomain claims
  under hub-managed bases (e.g. `inbox-demo.vito.gg`).
- `is_custom = true`, `challenge = Some(<32B>)`, `status =
  Pending` until DNS verification flips it to `Verified` then
  `Active` — these are BYO custom domains.

### Future record types

- `Photo`, `Note`, `File` (v1.1+).

Until each section lands here, the source-of-truth Rust types live
in `core::types::*` and the byte layouts are governed by
[`data-format.md`](data-format.md).
