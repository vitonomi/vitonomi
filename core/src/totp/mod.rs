//! RFC 6238 TOTP generator.
//!
//! Pure-Rust HOTP step (RFC 4226) over HMAC-{SHA-1,SHA-256,SHA-512},
//! parameterised by [`crate::types::credential::TotpConfig`]. No
//! network access, no clock access — callers pass `now_unix_secs`
//! explicitly so tests can pin time to RFC 6238 Appendix B vectors.
//!
//! Also provides `otpauth://` URI parsing / formatting for importer
//! and exporter use.
//!
//! Test vectors live inline in the module's `#[cfg(test)]` block;
//! they cover every Appendix B value at SHA-1 / SHA-256 / SHA-512
//! across the six standard timestamps.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::errors::{CryptoError, ProtocolError};
use crate::types::credential::{SecretBytes, TotpAlg, TotpConfig};

const RFC4648_BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Generate the TOTP code for `cfg` at `now_unix_secs`. Output is a
/// zero-padded decimal string of `cfg.digits` digits.
///
/// # Errors
///
/// `CryptoError::Kdf` if `cfg.digits` is outside RFC 6238's
/// supported range (6, 7, or 8).
pub fn generate(cfg: &TotpConfig, now_unix_secs: u64) -> Result<String, CryptoError> {
    if !(6..=8).contains(&cfg.digits) {
        return Err(CryptoError::Kdf(format!(
            "TOTP digits {} outside RFC 6238 range [6, 8]",
            cfg.digits
        )));
    }
    if cfg.period_secs == 0 {
        return Err(CryptoError::Kdf("TOTP period_secs must be > 0".into()));
    }
    let counter = now_unix_secs / u64::from(cfg.period_secs);
    Ok(hotp_truncate(cfg, counter))
}

/// Compute the TOTP step number (counter) at `now_unix_secs` for
/// `cfg`. Useful for "watch" UIs that want to render seconds-until-
/// rotation.
#[must_use]
pub fn step_at(cfg: &TotpConfig, now_unix_secs: u64) -> u64 {
    now_unix_secs / u64::from(cfg.period_secs)
}

/// Unix-seconds timestamp at which the next TOTP window begins for
/// `cfg`. Useful for sleep / refresh scheduling.
#[must_use]
pub fn next_window(cfg: &TotpConfig, now_unix_secs: u64) -> u64 {
    let period = u64::from(cfg.period_secs);
    let current = step_at(cfg, now_unix_secs);
    (current + 1) * period
}

/// Format a [`TotpConfig`] + label as an `otpauth://totp/...` URI.
/// Output is suitable for QR-code rendering or copy-to-clipboard
/// hand-off.
#[must_use]
pub fn to_otpauth_uri(label: &str, cfg: &TotpConfig) -> String {
    let alg = match cfg.algorithm {
        TotpAlg::Sha1 => "SHA1",
        TotpAlg::Sha256 => "SHA256",
        TotpAlg::Sha512 => "SHA512",
    };
    let secret_b32 = base32_encode(cfg.secret.expose_secret());
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&algorithm={alg}&digits={d}&period={p}",
        label = url_path_encode(label),
        d = cfg.digits,
        p = cfg.period_secs,
    )
}

/// Parse an `otpauth://totp/...` URI into a `(label, TotpConfig)`
/// pair.
///
/// # Errors
///
/// `ProtocolError::Malformed` for any structural problem (wrong
/// scheme, missing required parameter, malformed base32 secret,
/// unsupported algorithm name).
pub fn parse_otpauth_uri(uri: &str) -> Result<(String, TotpConfig), ProtocolError> {
    // Strip `otpauth://totp/`.
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| ProtocolError::Malformed("otpauth URI must start with otpauth://totp/".into()))?;
    let (label_pct, query) = rest
        .split_once('?')
        .ok_or_else(|| ProtocolError::Malformed("otpauth URI missing query string".into()))?;
    let label = url_path_decode(label_pct);

    let mut secret_b32: Option<&str> = None;
    let mut alg: TotpAlg = TotpAlg::Sha1;
    let mut digits: u8 = 6;
    let mut period: u32 = 30;

    for kv in query.split('&') {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| ProtocolError::Malformed(format!("malformed query pair {kv:?}")))?;
        match k {
            "secret" => secret_b32 = Some(v),
            "algorithm" => {
                alg = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlg::Sha1,
                    "SHA256" => TotpAlg::Sha256,
                    "SHA512" => TotpAlg::Sha512,
                    other => {
                        return Err(ProtocolError::Malformed(format!(
                            "unsupported TOTP algorithm {other:?}"
                        )))
                    }
                }
            }
            "digits" => {
                digits = v
                    .parse()
                    .map_err(|e| ProtocolError::Malformed(format!("digits parse: {e}")))?;
            }
            "period" => {
                period = v
                    .parse()
                    .map_err(|e| ProtocolError::Malformed(format!("period parse: {e}")))?;
            }
            // Ignore issuer + other optional params for now.
            _ => {}
        }
    }

    let b32 = secret_b32
        .ok_or_else(|| ProtocolError::Malformed("otpauth URI missing secret= parameter".into()))?;
    let secret = base32_decode(b32)
        .map_err(|e| ProtocolError::Malformed(format!("base32 secret decode: {e}")))?;

    Ok((
        label,
        TotpConfig {
            secret: SecretBytes::new(secret),
            algorithm: alg,
            digits,
            period_secs: period,
        },
    ))
}

// ── HOTP step ────────────────────────────────────────────────────

fn hotp_truncate(cfg: &TotpConfig, counter: u64) -> String {
    let counter_be = counter.to_be_bytes();
    let mac: Vec<u8> = match cfg.algorithm {
        TotpAlg::Sha1 => hmac_sha1(cfg.secret.expose_secret(), &counter_be),
        TotpAlg::Sha256 => hmac_sha256(cfg.secret.expose_secret(), &counter_be),
        TotpAlg::Sha512 => hmac_sha512(cfg.secret.expose_secret(), &counter_be),
    };
    // Dynamic truncation: low 4 bits of the last byte → offset.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    // 31-bit binary code from 4 bytes starting at offset.
    let bin_code = ((u32::from(mac[offset]) & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);
    let modulus = 10u32.pow(u32::from(cfg.digits));
    let value = bin_code % modulus;
    format!("{value:0width$}", width = cfg.digits as usize)
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC-SHA1 accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha512>>::new_from_slice(key).expect("HMAC-SHA512 accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

// ── base32 codec (RFC 4648, with optional padding on parse) ─────

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buf = (buf << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1f) as usize;
            out.push(RFC4648_BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1f) as usize;
        out.push(RFC4648_BASE32_ALPHABET[idx] as char);
    }
    // Pad to multiple of 8.
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

fn base32_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity((s.len() / 8) * 5);
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for ch in s.chars() {
        if ch == '=' {
            continue;
        }
        let upper = ch.to_ascii_uppercase();
        let val = match upper {
            'A'..='Z' => (upper as u8) - b'A',
            '2'..='7' => (upper as u8) - b'2' + 26,
            other => return Err(format!("non-base32 char {other:?}")),
        };
        buf = (buf << 5) | u64::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

// ── minimal URL-path percent encode/decode (label only) ─────────

fn url_path_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'@' | b':') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

fn url_path_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) =
                (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
            {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // The label is documented as UTF-8; lossy decode falls back to
    // replacement on the unlikely case of malformed bytes.
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(secret: &[u8], alg: TotpAlg) -> TotpConfig {
        TotpConfig {
            secret: SecretBytes::new(secret.to_vec()),
            algorithm: alg,
            digits: 8,
            period_secs: 30,
        }
    }

    // Seeds from RFC 6238 Appendix B.
    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    /// RFC 6238 Appendix B test vectors. Each row: (now_secs,
    /// expected_sha1, expected_sha256, expected_sha512).
    fn rfc_vectors() -> &'static [(u64, &'static str, &'static str, &'static str)] {
        &[
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ]
    }

    #[test]
    fn rfc6238_appendix_b_sha1() {
        let c = cfg(SEED_SHA1, TotpAlg::Sha1);
        for &(t, sha1, _, _) in rfc_vectors() {
            assert_eq!(generate(&c, t).unwrap(), sha1, "SHA-1 at T = {t}");
        }
    }

    #[test]
    fn rfc6238_appendix_b_sha256() {
        let c = cfg(SEED_SHA256, TotpAlg::Sha256);
        for &(t, _, sha256, _) in rfc_vectors() {
            assert_eq!(generate(&c, t).unwrap(), sha256, "SHA-256 at T = {t}");
        }
    }

    #[test]
    fn rfc6238_appendix_b_sha512() {
        let c = cfg(SEED_SHA512, TotpAlg::Sha512);
        for &(t, _, _, sha512) in rfc_vectors() {
            assert_eq!(generate(&c, t).unwrap(), sha512, "SHA-512 at T = {t}");
        }
    }

    #[test]
    fn digits_six_and_seven_supported() {
        // 6 and 7 are common; the RFC allows {6,7,8}. 8 is covered
        // by the appendix tests above.
        let mut c = cfg(SEED_SHA1, TotpAlg::Sha1);
        c.digits = 6;
        let s6 = generate(&c, 59).unwrap();
        assert_eq!(s6.len(), 6);
        c.digits = 7;
        let s7 = generate(&c, 59).unwrap();
        assert_eq!(s7.len(), 7);
        // SHA-1 / T=59 / 8 digits = 94287082; truncating to 7 digits
        // => last 7 chars by mod-10^7 = 4287082; to 6 => 287082.
        assert_eq!(s7, "4287082");
        assert_eq!(s6, "287082");
    }

    #[test]
    fn digits_outside_supported_range_rejected() {
        let mut c = cfg(SEED_SHA1, TotpAlg::Sha1);
        c.digits = 5;
        assert!(generate(&c, 0).is_err());
        c.digits = 9;
        assert!(generate(&c, 0).is_err());
    }

    #[test]
    fn period_secs_zero_rejected() {
        let mut c = cfg(SEED_SHA1, TotpAlg::Sha1);
        c.period_secs = 0;
        assert!(generate(&c, 0).is_err());
    }

    #[test]
    fn step_increments_at_period_boundary() {
        let c = cfg(SEED_SHA1, TotpAlg::Sha1);
        // Period 30, T=59 → step 1; T=60 → step 2.
        assert_eq!(step_at(&c, 59), 1);
        assert_eq!(step_at(&c, 60), 2);
        assert_eq!(next_window(&c, 59), 60);
        assert_eq!(next_window(&c, 60), 90);
    }

    #[test]
    fn otpauth_round_trip_sha1_default() {
        let c = TotpConfig {
            secret: SecretBytes::new(SEED_SHA1.to_vec()),
            algorithm: TotpAlg::Sha1,
            digits: 6,
            period_secs: 30,
        };
        let uri = to_otpauth_uri("Netflix:birkeal@example.com", &c);
        let (label, parsed) = parse_otpauth_uri(&uri).unwrap();
        assert_eq!(label, "Netflix:birkeal@example.com");
        assert_eq!(parsed.algorithm, TotpAlg::Sha1);
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period_secs, 30);
        assert_eq!(parsed.secret.expose_secret(), SEED_SHA1);
    }

    #[test]
    fn otpauth_round_trip_sha256_8digit_60period() {
        let c = TotpConfig {
            secret: SecretBytes::new(SEED_SHA256.to_vec()),
            algorithm: TotpAlg::Sha256,
            digits: 8,
            period_secs: 60,
        };
        let uri = to_otpauth_uri("foo", &c);
        let (label, parsed) = parse_otpauth_uri(&uri).unwrap();
        assert_eq!(label, "foo");
        assert_eq!(parsed.algorithm, TotpAlg::Sha256);
        assert_eq!(parsed.digits, 8);
        assert_eq!(parsed.period_secs, 60);
        assert_eq!(parsed.secret.expose_secret(), SEED_SHA256);
    }

    #[test]
    fn otpauth_rejects_wrong_scheme() {
        assert!(parse_otpauth_uri("https://example.com/").is_err());
        assert!(parse_otpauth_uri("otpauth://hotp/x?secret=ABCD").is_err());
    }

    #[test]
    fn otpauth_rejects_missing_secret() {
        assert!(parse_otpauth_uri("otpauth://totp/x?digits=6").is_err());
    }

    #[test]
    fn otpauth_rejects_bad_algorithm() {
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5").is_err());
    }

    #[test]
    fn base32_round_trip_arbitrary_bytes() {
        for input in [
            b"".as_slice(),
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0u8; 16],
            &[0xffu8; 17],
        ] {
            let enc = base32_encode(input);
            assert_eq!(enc.len() % 8, 0, "padded to multiple of 8: {enc}");
            let dec = base32_decode(&enc).unwrap();
            assert_eq!(&dec, input);
        }
    }

    #[test]
    fn base32_decode_rejects_non_alphabet_chars() {
        assert!(base32_decode("!!!!").is_err());
        // '1' and '8' / '9' / '0' are NOT in RFC 4648 base32.
        assert!(base32_decode("01234567").is_err());
    }
}
