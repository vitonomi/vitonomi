//! Encoding helpers — base64url, hex, constant-time comparison, and
//! deterministic CBOR.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::errors::ProtocolError;

/// Encode bytes as URL-safe base64 with no padding.
#[must_use]
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode URL-safe base64 (no padding).
///
/// # Errors
///
/// Returns `ProtocolError::Malformed` on invalid base64 input.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, ProtocolError> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| ProtocolError::Malformed(format!("base64url decode: {e}")))
}

/// Encode bytes as lowercase hex.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode lowercase or uppercase hex.
///
/// # Errors
///
/// Returns `ProtocolError::Malformed` on invalid hex.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, ProtocolError> {
    hex::decode(s).map_err(|e| ProtocolError::Malformed(format!("hex decode: {e}")))
}

/// Constant-time byte equality. Returns `true` iff `a == b`.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Encode a value as deterministic CBOR (RFC 8949 strict mode).
///
/// # Errors
///
/// Returns `ProtocolError::Cbor` if encoding fails.
pub fn cbor_to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| ProtocolError::Cbor(format!("encode: {e}")))?;
    Ok(buf)
}

/// Decode a CBOR-encoded value.
///
/// # Errors
///
/// Returns `ProtocolError::Cbor` if decoding fails.
pub fn cbor_from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    ciborium::from_reader(bytes).map_err(|e| ProtocolError::Cbor(format!("decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_round_trip() {
        let data: &[u8] = &[0, 1, 2, 3, 4, 250, 251, 252, 253, 254, 255];
        let s = b64url_encode(data);
        assert!(!s.contains('='), "no padding allowed");
        assert_eq!(b64url_decode(&s).unwrap(), data);
    }

    #[test]
    fn b64url_rejects_garbage() {
        assert!(b64url_decode("!!!!").is_err());
    }

    #[test]
    fn hex_round_trip() {
        let data: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0x42];
        assert_eq!(hex_encode(data), "deadbeef42");
        assert_eq!(hex_decode("deadbeef42").unwrap(), data);
        assert_eq!(hex_decode("DEADBEEF42").unwrap(), data);
    }

    #[test]
    fn ct_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn cbor_round_trip_simple() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Probe {
            a: u32,
            b: String,
            c: Vec<u8>,
        }
        let p = Probe {
            a: 42,
            b: "hello".into(),
            c: vec![1, 2, 3],
        };
        let bytes = cbor_to_vec(&p).unwrap();
        let back: Probe = cbor_from_slice(&bytes).unwrap();
        assert_eq!(p, back);
    }
}
