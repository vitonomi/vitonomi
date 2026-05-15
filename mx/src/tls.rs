//! Wildcard TLS for the SMTP STARTTLS path.
//!
//! Dev: rcgen-generated self-signed cert with a single SAN
//! `*.<base_domain>` (e.g. `*.vito.gg`). Prod: operator-supplied
//! PEMs from ACME DNS-01.
//!
//! **Privacy invariant**: the cert MUST be a wildcard with a
//! single SAN entry — issuing per-subdomain certs would post
//! every claimed handle to public Certificate Transparency
//! logs, defeating the no-username-in-DNS guarantee. Slice 9's
//! `tls_wildcard_cert_no_per_subdomain_san` test gates this in
//! CI.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use crate::state_dir;

/// Loaded TLS material ready for `tokio-rustls`.
pub struct TlsMaterial {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// Resolve TLS material. If both cert and key paths are blank
/// in the config, generate a dev wildcard cert at
/// `<data_dir>/tls/{cert,key}.pem` and load it. Otherwise
/// load the configured PEMs.
///
/// # Errors
///
/// File-system / rcgen / parse failures.
pub fn resolve(
    data_dir: &Path,
    base_domain: &str,
    configured_cert: &str,
    configured_key: &str,
) -> anyhow::Result<TlsMaterial> {
    if configured_cert.is_empty() && configured_key.is_empty() {
        let cert_path = state_dir::tls_cert_path(data_dir);
        let key_path = state_dir::tls_key_path(data_dir);
        ensure_dev_wildcard_cert(data_dir, &cert_path, &key_path, base_domain)?;
        load(&cert_path, &key_path)
    } else {
        load(Path::new(configured_cert), Path::new(configured_key))
    }
}

fn ensure_dev_wildcard_cert(
    data_dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    base_domain: &str,
) -> anyhow::Result<()> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    state_dir::ensure_data_dir(data_dir)?;
    // SINGLE wildcard SAN. Don't add `localhost` / `127.0.0.1` —
    // the cert lives under the wildcard-only invariant for the
    // CT-leak protection.
    let params = rcgen::CertificateParams::new(vec![format!("*.{base_domain}")])
        .map_err(|e| anyhow!("rcgen params: {e}"))?;
    let key_pair = rcgen::KeyPair::generate().map_err(|e| anyhow!("rcgen key_pair: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("rcgen self_signed: {e}"))?;
    state_dir::write_secure(cert_path, cert.pem().as_bytes())?;
    state_dir::write_secure(key_path, key_pair.serialize_pem().as_bytes())?;
    tracing::info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        base_domain = base_domain,
        "generated dev wildcard TLS cert"
    );
    Ok(())
}

fn load(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsMaterial> {
    let cert_pem =
        std::fs::read(cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    let key_pem =
        std::fs::read(key_path).with_context(|| format!("read {}", key_path.display()))?;
    Ok(TlsMaterial { cert_pem, key_pem })
}

/// Extract the SAN list from a PEM-encoded leaf cert. Used by
/// the slice-7 CI gate that asserts there's exactly one
/// wildcard SAN and no per-subdomain entries.
///
/// # Errors
///
/// Failure to decode the PEM / parse SAN entries.
pub fn extract_sans(cert_pem: &[u8]) -> anyhow::Result<Vec<String>> {
    use rustls_pemfile::Item;
    let mut sans = Vec::new();
    let mut slice: &[u8] = cert_pem;
    let der = loop {
        match rustls_pemfile::read_one(&mut slice).map_err(|e| anyhow!("PEM: {e}"))? {
            Some(Item::X509Certificate(d)) => break d,
            None => return Err(anyhow!("no leaf certificate in PEM")),
            _ => continue,
        }
    };
    // Hand-roll a minimal X.509 SAN extension scan. The cert
    // format is well-defined enough that we can locate the
    // `subjectAltName` extension by OID 2.5.29.17 within the
    // DER bytes without pulling a full ASN.1 dep. This is
    // best-effort — parse failures fall back to empty SAN
    // list, which causes the wildcard-SAN-only test to fail
    // safely (preferring false-positive over silent miss).
    //
    // The OID 2.5.29.17 = bytes 0x06, 0x03, 0x55, 0x1d, 0x11.
    const SAN_OID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
    let bytes = der.as_ref();
    let Some(idx) = find_subsequence(bytes, SAN_OID) else {
        return Ok(sans);
    };
    // Skip OID; the next byte is BOOLEAN (critical) flag or
    // OCTET STRING tag. Move ahead until we hit 0x04 (OCTET
    // STRING tag for the extnValue), then read the embedded
    // SEQUENCE OF GeneralName.
    let mut i = idx + SAN_OID.len();
    while i < bytes.len() && bytes[i] != 0x04 {
        i += 1;
    }
    if i >= bytes.len() {
        return Ok(sans);
    }
    // Skip OCTET STRING tag + length(s).
    i += 1;
    let (extn_len, advance) = decode_der_length(&bytes[i..])?;
    i += advance;
    let extn_end = i + extn_len;
    if extn_end > bytes.len() {
        return Ok(sans);
    }
    // Inside the extn value: SEQUENCE OF GeneralName. Walk
    // GeneralName entries — we only care about dNSName (tag
    // 0x82, IMPLICIT [2] IA5String).
    if bytes[i] != 0x30 {
        return Ok(sans);
    }
    i += 1;
    let (_, advance) = decode_der_length(&bytes[i..])?;
    i += advance;
    while i < extn_end {
        let tag = bytes[i];
        i += 1;
        let (len, advance) = decode_der_length(&bytes[i..])?;
        i += advance;
        if tag == 0x82 {
            let s = std::str::from_utf8(&bytes[i..i + len])
                .map_err(|e| anyhow!("SAN dNSName UTF-8: {e}"))?
                .to_string();
            sans.push(s);
        }
        i += len;
    }
    Ok(sans)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn decode_der_length(bytes: &[u8]) -> anyhow::Result<(usize, usize)> {
    if bytes.is_empty() {
        return Err(anyhow!("DER length: out of bytes"));
    }
    let first = bytes[0];
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || bytes.len() < 1 + n {
        return Err(anyhow!("DER length: bad form"));
    }
    let mut len: usize = 0;
    for &b in &bytes[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_wildcard_cert_has_exactly_one_wildcard_san() {
        let tmp = tempfile::tempdir().unwrap();
        let mat = resolve(tmp.path(), "vito.gg", "", "").unwrap();
        let sans = extract_sans(&mat.cert_pem).unwrap();
        assert_eq!(sans, vec!["*.vito.gg".to_string()]);
    }

    #[test]
    fn resolve_persists_cert_across_calls() {
        let tmp = tempfile::tempdir().unwrap();
        let a = resolve(tmp.path(), "vito.gg", "", "").unwrap();
        let b = resolve(tmp.path(), "vito.gg", "", "").unwrap();
        assert_eq!(a.cert_pem, b.cert_pem);
        assert_eq!(a.key_pem, b.key_pem);
    }

    #[test]
    fn dev_cert_san_does_not_contain_per_subdomain_entry() {
        // The CI gate that protects against operator
        // misconfiguration: assert no SAN looks like a
        // specific (non-wildcard) subdomain of the base.
        let tmp = tempfile::tempdir().unwrap();
        let mat = resolve(tmp.path(), "vito.gg", "", "").unwrap();
        let sans = extract_sans(&mat.cert_pem).unwrap();
        for s in &sans {
            // Wildcard `*.vito.gg` is allowed; anything else
            // ending in `.vito.gg` would be a per-subdomain
            // SAN and a CT-leak risk.
            if s.ends_with(".vito.gg") {
                assert!(
                    s.starts_with("*."),
                    "SAN {s:?} is a per-subdomain entry — would leak into \
                     Certificate Transparency logs. Wildcard-only invariant violated."
                );
            }
        }
    }
}
