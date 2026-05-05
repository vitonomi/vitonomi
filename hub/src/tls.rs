//! TLS bootstrap. In dev mode (no `cert_pem`/`key_pem` configured)
//! the hub generates a self-signed certificate via `rcgen`, persists
//! it under `data_dir/dev-cert.pem` + `dev-key.pem` (mode 0600),
//! and computes the SPKI fingerprint that vaults pin via the
//! invite token's `hub_cert_fingerprint`.
//!
//! In prod mode, both fields point at PEM files on disk. Either
//! way, the fingerprint is the SPKI SHA-256 of the leaf cert,
//! base64url-encoded with no padding.

use std::path::Path;

use anyhow::{anyhow, Context as _};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::config::HubConfig;

/// Concrete TLS material loaded from disk (or generated in dev mode).
pub struct TlsMaterial {
    /// Leaf-cert PEM bytes.
    pub cert_pem: Vec<u8>,
    /// Key PEM bytes.
    pub key_pem: Vec<u8>,
    /// `sha256:<base64url-no-padding>` of the leaf cert's SPKI.
    /// Vault stores this in `vault.toml` after `accept` and pins
    /// it on every WS connect.
    pub spki_fingerprint: String,
}

/// Resolve TLS material from config. Generates dev cert if both
/// `cert_pem` and `key_pem` are blank.
///
/// # Errors
///
/// File-system / parsing failures.
pub fn resolve(cfg: &HubConfig) -> anyhow::Result<TlsMaterial> {
    if cfg.tls.cert_pem.is_empty() && cfg.tls.key_pem.is_empty() {
        let cert_path = cfg.paths.data_dir.join("dev-cert.pem");
        let key_path = cfg.paths.data_dir.join("dev-key.pem");
        ensure_dev_cert(&cfg.paths.data_dir, &cert_path, &key_path)?;
        load(&cert_path, &key_path)
    } else {
        load(Path::new(&cfg.tls.cert_pem), Path::new(&cfg.tls.key_pem))
    }
}

fn ensure_dev_cert(data_dir: &Path, cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("create data dir {}", data_dir.display()))?;
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .map_err(|e| anyhow!("rcgen params: {e}"))?;
    let key_pair = rcgen::KeyPair::generate().map_err(|e| anyhow!("rcgen key_pair: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("rcgen self_signed: {e}"))?;

    write_secure(cert_path, cert.pem().as_bytes())?;
    write_secure(key_path, key_pair.serialize_pem().as_bytes())?;
    tracing::info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "generated dev self-signed certificate"
    );
    Ok(())
}

fn write_secure(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    use std::io::Write as _;
    f.write_all(contents)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn load(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsMaterial> {
    let cert_pem =
        std::fs::read(cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    let key_pem =
        std::fs::read(key_path).with_context(|| format!("read {}", key_path.display()))?;
    let spki_fingerprint = compute_spki_fingerprint(&cert_pem, cert_path)?;
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        spki_fingerprint,
    })
}

fn compute_spki_fingerprint(cert_pem: &[u8], cert_path: &Path) -> anyhow::Result<String> {
    let mut slice: &[u8] = cert_pem;
    let mut der_iter = rustls_pemfile::certs(&mut slice);
    let leaf = der_iter
        .next()
        .ok_or_else(|| anyhow!("{} contains no certificates", cert_path.display()))?
        .map_err(|e| anyhow!("parse cert: {e}"))?;
    let spki = extract_spki(leaf.as_ref())
        .ok_or_else(|| anyhow!("could not extract SubjectPublicKeyInfo from leaf cert"))?;
    let mut h = Sha256::new();
    h.update(spki);
    let digest = h.finalize();
    Ok(format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest)))
}

/// Pull the SPKI bytes out of a DER-encoded X.509 certificate.
///
/// We intentionally keep this lightweight (parsing one outer
/// SEQUENCE → tbsCertificate SEQUENCE → skip 6 fields → SPKI
/// SEQUENCE) rather than pulling in a heavyweight ASN.1 crate.
fn extract_spki(cert_der: &[u8]) -> Option<&[u8]> {
    let mut p = Asn1Parser {
        buf: cert_der,
        pos: 0,
    };
    // outer Certificate SEQUENCE
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
    // version [0] EXPLICIT (optional, default v1) — skip if present
    if tbs.peek_tag() == Some(0xa0) {
        tbs.read_tlv()?;
    }
    // serialNumber INTEGER
    tbs.read_tlv()?;
    // signature AlgorithmIdentifier (SEQUENCE)
    tbs.read_tlv()?;
    // issuer Name (SEQUENCE)
    tbs.read_tlv()?;
    // validity Validity (SEQUENCE)
    tbs.read_tlv()?;
    // subject Name (SEQUENCE)
    tbs.read_tlv()?;
    // subjectPublicKeyInfo SEQUENCE — we want the WHOLE TLV including header
    let spki = tbs.read_tlv_with_header()?;
    Some(spki)
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

/// Build a `rustls::ServerConfig` from PEM bytes.
///
/// # Errors
///
/// Parsing or builder failures.
pub fn server_config(
    material: &TlsMaterial,
) -> anyhow::Result<std::sync::Arc<rustls::ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cert_slice: &[u8] = &material.cert_pem;
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_slice)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("parse certs: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates in cert_pem"));
    }
    let mut key_slice: &[u8] = &material.key_pem;
    let key = rustls_pemfile::private_key(&mut key_slice)
        .map_err(|e| anyhow!("parse private key: {e}"))?
        .ok_or_else(|| anyhow!("no private key found"))?;
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("rustls server config: {e}"))?;
    Ok(std::sync::Arc::new(cfg))
}
