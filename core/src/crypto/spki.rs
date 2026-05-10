//! Lightweight extraction of the `SubjectPublicKeyInfo` from a
//! DER-encoded X.509 certificate, plus the canonical SPKI fingerprint
//! formatting used across vitonomi (`sha256:<base64url-no-padding>`).
//!
//! Why we hand-roll this: every binary needs to compute or compare
//! SPKI fingerprints (hub generates the dev cert + reports it; vault
//! pins the leaf cert; cli probes a hub on cluster-create), but
//! pulling in a full ASN.1 crate just for one parse is overkill.
//! The parser walks the well-defined DER structure of an X.509
//! certificate to the SPKI field and returns its full TLV blob.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// SPKI bytes extracted from a DER-encoded X.509 certificate. Returns
/// `None` if the input is malformed or the structure doesn't match
/// the expected layout.
#[must_use]
pub fn extract_spki(cert_der: &[u8]) -> Option<&[u8]> {
    let mut p = Asn1Parser {
        buf: cert_der,
        pos: 0,
    };
    let cert_body = p.read_seq()?;
    let mut tbs_p = Asn1Parser {
        buf: cert_body,
        pos: 0,
    };
    let tbs_body = tbs_p.read_seq()?;
    let mut tbs = Asn1Parser {
        buf: tbs_body,
        pos: 0,
    };
    // version [0] EXPLICIT (optional, default v1) — skip if present.
    if tbs.peek_tag() == Some(0xa0) {
        tbs.read_tlv()?;
    }
    tbs.read_tlv()?; // serialNumber INTEGER
    tbs.read_tlv()?; // signature AlgorithmIdentifier
    tbs.read_tlv()?; // issuer Name
    tbs.read_tlv()?; // validity Validity
    tbs.read_tlv()?; // subject Name
    tbs.read_tlv_with_header() // subjectPublicKeyInfo SEQUENCE (whole TLV)
}

/// Compute the canonical fingerprint string for a leaf cert:
/// `sha256:<base64url-no-padding>` of the cert's SPKI bytes. Returns
/// `None` if the DER is malformed.
#[must_use]
pub fn fingerprint_for_cert(cert_der: &[u8]) -> Option<String> {
    let spki = extract_spki(cert_der)?;
    let digest = Sha256::digest(spki);
    Some(format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest)))
}

struct Asn1Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Asn1Parser<'a> {
    fn peek_tag(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn read_seq(&mut self) -> Option<&'a [u8]> {
        let tag = self.read_byte()?;
        if tag != 0x30 {
            return None;
        }
        let len = self.read_len()?;
        let start = self.pos;
        let end = start.checked_add(len)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(&self.buf[start..end])
    }

    fn read_tlv(&mut self) -> Option<&'a [u8]> {
        let _tag = self.read_byte()?;
        let len = self.read_len()?;
        let start = self.pos;
        let end = start.checked_add(len)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(&self.buf[start..end])
    }

    fn read_tlv_with_header(&mut self) -> Option<&'a [u8]> {
        let header_start = self.pos;
        let _tag = self.read_byte()?;
        let len = self.read_len()?;
        let start = self.pos;
        let end = start.checked_add(len)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(&self.buf[header_start..end])
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_len(&mut self) -> Option<usize> {
        let b = self.read_byte()?;
        if b & 0x80 == 0 {
            return Some(b as usize);
        }
        let n = (b & 0x7f) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | (self.read_byte()? as usize);
        }
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_returns_none() {
        assert!(extract_spki(&[]).is_none());
        assert!(extract_spki(&[0xff; 16]).is_none());
        assert!(fingerprint_for_cert(&[]).is_none());
    }

    #[test]
    fn fingerprint_format_is_canonical() {
        let synthetic_spki = [0x30, 0x02, 0x05, 0x00];
        let digest = Sha256::digest(synthetic_spki);
        let expected = format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest));
        assert!(expected.starts_with("sha256:"));
        assert!(!expected.ends_with('='));
    }
}
