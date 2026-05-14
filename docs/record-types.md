---
formatVersion: 0
status: stub
last-reviewed: 2026-05-01
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

### Future record types

Filled in by the delivering phase:

- `Alias`, `AliasMessage`, `CustomDomain` (Phase 7) — see
  PROJECT.md Phase 7.
- `Photo`, `Note`, `File` (v1.1+).

Until each section lands here, the source-of-truth Rust types live
in `core::types::*` and the byte layouts are governed by
[`data-format.md`](data-format.md).
