---
formatVersion: 1
status: stable
last-reviewed: 2026-05-03
---

# Streaming wire protocols

This document specifies the vault ↔ hub streaming protocol that
sits alongside the HTTP control plane in
[`api-spec.yaml`](api-spec.yaml). The hub serves it on
`wss://<hub>/v1/vault-bus`; vaults dial outbound and authenticate
each connection with a signed challenge.

The mini-MVP transport is **WebSocket-over-TLS** via
`tokio-tungstenite` + `rustls`. libp2p-rs is the v1.1+ target;
swapping it in is a single constructor change at the
`vitonomi-core::protocol::vault_bus::VaultBus` trait boundary —
none of the frame layout below changes.

## Endpoint

| Field           | Value                                                    |
| --------------- | -------------------------------------------------------- |
| URL path        | `/v1/vault-bus`                                          |
| Scheme          | `wss://` (TLS required; vault pins SPKI fingerprint)     |
| Method          | HTTP `GET` upgrade to WebSocket                          |
| Subprotocol     | `vitonomi.vault-bus.v1` (negotiated via `Sec-WebSocket-Protocol`) |
| Auth            | First-frame signed challenge (no bearer token on the upgrade request) |
| Frame format    | Length-prefixed CBOR — see [Frame format](#frame-format) |
| Idle timeout    | 90 s wall-clock without an inbound or outbound frame     |

The hub TLS cert SPKI is bound into the vault's invite token at
issue time (`hub_cert_fingerprint`). The vault's WebSocket client
MUST verify the live leaf-cert SPKI matches the persisted
fingerprint on every connect — system trust store is bypassed.

## Frame format

Every frame is a length-prefixed CBOR (RFC 8949 strict mode)
encoded `BusFrame` value (defined below). On the WebSocket layer,
each `BusFrame` is sent as a single **binary** message; text
messages are an error.

```text
┌──────────────────────────────────────────┐
│ length: u32 LE  │  cbor bytes (BusFrame) │
└──────────────────────────────────────────┘
```

The `length` prefix is a 4-byte little-endian unsigned integer
giving the byte length of the CBOR payload that follows.
WebSocket framing already provides a length, but the prefix is
mandatory so the same wire format works unchanged when the
transport swaps to libp2p-rs (which uses raw bidirectional byte
streams).

**Maximum frame size: 64 KiB.** Larger frames are a protocol
error and trigger an `Error` frame followed by close.

## Frame schemas

`BusFrame` is a tagged enum (`{ "kind": "...", ... }` JSON-style;
on the wire CBOR encodes the `kind` discriminator using serde's
default tagged-enum representation).

```rust
#[serde(tag = "kind", rename_all = "kebab-case")]
enum BusFrame {
    Challenge(ChallengeFrame),                   // hub → vault
    ChallengeResponse(ChallengeResponseFrame),   // vault → hub
    SessionEstablished(SessionEstablishedFrame), // hub → vault
    Heartbeat(HeartbeatFrame),                   // vault → hub
    ChainAppend(ChainAppendFrame),               // hub → vault
    ChainAdvertise(ChainAdvertiseFrame),         // either direction
    Error(ErrorFrame),                           // either direction
    Disconnect(DisconnectFrame),                 // either direction
}
```

The Rust struct definitions live at
`vitonomi/core/src/protocol/wire/vault_bus.rs`. They are the
authoritative byte layout — this document narrates them.

### `Challenge` (hub → vault)

```text
ChallengeFrame {
  challenge: {
    nonce: bytes(32),
    sent_at_ms: uint64,
  }
}
```

First frame from the hub on every successful upgrade. The vault
MUST sign `nonce || sent_at_ms_be8` (32 + 8 bytes, big-endian
timestamp suffix) with its persistent ML-DSA-65 secret key and
respond with `ChallengeResponse`.

### `ChallengeResponse` (vault → hub)

```text
ChallengeResponseFrame {
  vault_id: bytes(16),
  signature: bytes(~3309),  // ML-DSA-65 detached
}
```

Hub looks up the stored `vault_pubkey` for `vault_id`, verifies
the signature, and replies `SessionEstablished` on success or
`Error` (then close) on failure.

### `SessionEstablished` (hub → vault)

```text
SessionEstablishedFrame {
  session_id: string,
  chain_head: AdminChainEntry,
}
```

`chain_head` is the latest admin-chain entry the hub knows about.
The vault compares against its local chain copy: if the hub is
behind, the vault SHOULD push missing entries via the HTTP
`POST /v1/admin-chain/{cluster_id}` endpoint after the WebSocket
handshake completes; if the vault is behind, it SHOULD fetch
missing entries via `GET /v1/admin-chain/{cluster_id}` and verify
every signature against its locally stored cluster admin pubkey.

### `Heartbeat` (vault → hub)

```text
HeartbeatFrame {
  vault_id: bytes(16),
  ts_ms: uint64,
  signature: bytes(~3309),  // ML-DSA-65 over (vault_id || ts_ms_be8)
}
```

Vault sends one every **30 s** while connected. Hub updates
`vaults.last_seen` on each verified heartbeat. A missed
heartbeat for two intervals (60 s) marks the vault `offline` in
the cluster directory.

Heartbeats are signed because a passive observer with a hijacked
TLS session could otherwise spoof "still online" forever; the
signature ties each heartbeat to a fresh `ts_ms`.

### `ChainAppend` (hub → vault)

```text
ChainAppendFrame {
  entry: AdminChainEntryOuter,   // see data-format.md
}
```

Hub broadcasts a freshly admin-ratified admin-chain entry (e.g. a
new `vault-enroll` after the admin's next login) to every online
vault. The entry is the **outer envelope** — its `sealed_inner`
field is opaque to the hub. Receivers MUST:

1. Verify `sig_admin_outer` against the stored cluster admin
   pubkey.
2. Verify hash-link continuity against the entry they currently
   hold as head.
3. AEAD-open `sealed_inner` under `cluster_shared_key` and
   verify `sig_admin_inner` over the unsealed action+payload.

Failures send an `Error` frame and a `Disconnect`.

### `ChainAdvertise` (either direction)

```text
ChainAdvertiseFrame {
  cluster_id:    bytes(32),
  highest_seq:   uint64,
  head_hash:     bytes(32),    // sha256(CBOR(outer at seq = highest_seq))
}
```

Sent on every reconnect by both sides:
- The hub sends one immediately after `SessionEstablished`
  reporting its view of the chain head.
- The vault sends one at the same time reporting its local
  view.

If the two disagree the **vault is authoritative**. The hub's
chain copy is **advisory cache** — it cannot be trusted to serve
the canonical chain under hub-blindness because the hub cannot
read sealed payloads and so cannot detect content-level forks.

When a vault receives a `ChainAdvertise` indicating the hub is
*ahead* of its local copy, it issues `GET /v1/admin-chain/
{cluster_id}?from_seq=<vault_local + 1>` to catch up.

When a vault sees the hub is *behind* its local copy, it MUST
log + alert and request the same advertise from peer vaults via
the data-plane gossip channel (libp2p-rs in v1.1; for the
mini-MVP a vault MAY periodically push its `ChainAdvertise` to
known peer vault URLs over plain HTTPS, falling back to "warn
the user via CLI status" when no peer is reachable).

**Single-vault clusters have no peer to gossip with.** They
trade integrity-against-malicious-hub for the offline chain
backup that `vitonomi-cli` writes to the seed-phrase backup
file at every login. See
[`threat-model.md`](threat-model.md#adversarial-hub-against-chain-integrity).

### `Error` (either direction)

```text
ErrorFrame {
  code: string,        // e.g. "auth.signature_invalid"
  message: string,
}
```

Either side MAY send an `Error` frame followed by a `Disconnect`
when the connection is unrecoverable. Common codes:

| Code                          | Sender | Reason                                                  |
| ----------------------------- | ------ | ------------------------------------------------------- |
| `auth.signature_invalid`      | hub    | Challenge response did not verify against stored pubkey |
| `auth.unknown_vault`          | hub    | `vault_id` not in cluster                               |
| `auth.heartbeat_invalid`      | hub    | Heartbeat signature failed verification                 |
| `auth.heartbeat_replay`       | hub    | `ts_ms` decreased relative to a previous heartbeat      |
| `protocol.malformed`          | either | CBOR decode failure or schema mismatch                  |
| `protocol.frame_too_large`    | either | Frame exceeded 64 KiB                                   |
| `protocol.unsupported_kind`   | either | Frame kind not in this version's enum                   |
| `chain.signature_invalid`     | vault  | `ChainAppend` outer or inner signature failed           |
| `chain.hash_link_break`       | vault  | `prev_hash` ≠ local head's hash                         |
| `chain.seal_open_failed`      | vault  | AEAD-open of `sealed_inner` failed (wrong key / tamper) |
| `chain.advertise_mismatch`    | vault  | Hub advertised a head behind local; manual reconciliation required |
| `chain.key_epoch_stale`       | vault  | Outer `key_epoch` newer than vault's; need cluster-key refresh |

### `Disconnect` (either direction)

```text
DisconnectFrame {
  reason: string,
}
```

Graceful shutdown signal. Sender MAY follow with a WebSocket
close (status code `1000`).

## Reconnection

Vaults reconnect with **exponential backoff capped at 60 s**:
1, 2, 4, 8, 16, 32, 60, 60, 60, ... seconds between attempts.
Backoff resets to 1 s on the first successfully established
session (i.e. after `SessionEstablished` is received).

On every reconnect the vault re-runs the full challenge handshake
(no resumption). Sessions are not durable across hub restarts.

## Concurrency

A single `vault_id` MAY hold at most one active session. If the
hub receives a successful `ChallengeResponse` while another
session for the same `vault_id` is open, the hub closes the
older session with `Disconnect { reason: "superseded" }` and
keeps the new one. This handles the common case of a vault
restart where the hub hasn't yet noticed the dropped TCP
connection.

## TLS pinning details

The vault's invite token (see
[`api-spec.yaml#InviteTokenBody`](api-spec.yaml)) carries
`hub_cert_fingerprint` in the form
`sha256:<base64url-no-padding>`. The fingerprint is the SHA-256
of the leaf cert's **SPKI** (not the whole cert) — stable across
cert renewal as long as the keypair is rotated separately.

The vault MUST:
1. Reject the connection if no certificate fingerprint is cached
   AND no invite is present (i.e. before first enrollment).
2. After enrollment, reject the connection if the leaf cert's
   SPKI hash does not match the cached `hub_cert_fingerprint`.
3. Skip system trust-store verification entirely (the embedded
   fingerprint is the only trust anchor for vault ↔ hub).

`hub_cert_fingerprint` is rewritten by `vitonomi-vault set-hub`
when migrating to a new hub; the value comes from the new hub's
admin-issued invite (or is supplied directly via
`--fingerprint <fp>`).

## Cross-references

- HTTP control plane: [`api-spec.yaml`](api-spec.yaml).
- Architecture overview: [`architecture.md`](architecture.md).
- Admin-chain byte layout: [`data-format.md`](data-format.md).
- Threat model — malicious hub / malicious vault:
  [`threat-model.md`](threat-model.md).
- Trait surface: `vitonomi-core::protocol::vault_bus`.
- Frame structs: `vitonomi-core::protocol::wire::vault_bus`.
