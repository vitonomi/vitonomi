//! WebSocket vault-bus. Mounted at `/v1/vault-bus` with subprotocol
//! `vitonomi.vault-bus.v1`. Frames are length-prefixed CBOR — see
//! `../../docs/protocol.md` for the wire format.

pub mod vault_bus;
