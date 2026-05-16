//! `Subdomain` — the namespace primitive for vitonomi mail
//! addresses on a hub-managed base domain.
//!
//! A user claims a subdomain (e.g. `inbox-demo`) under a
//! configured base domain (e.g. `vito.gg`); aliases are then
//! addressable as `<alias>@<subdomain>.<base>`. The newtype
//! holds **only the local part** — the base domain is configured
//! per-deployment and joined at use sites via [`full_domain`].
//!
//! # Privacy invariant
//!
//! The user's `username` (login identifier) MUST NOT appear in
//! any public DNS namespace. [`Subdomain::parse_against_username`]
//! enforces this client-side. **The hub does not re-check** (see
//! `docs/threat-model.md#relaxed_posture.client_side_username_check_only`)
//! — the trade-off is that a patched / malicious client could
//! bypass and claim its own username; the worst case is the user
//! ends up with their own username as a public subdomain.
//!
//! # Reserved names
//!
//! [`is_reserved_subdomain`] is the security-critical hard-coded
//! reject list (`www`, `mail`, `mx`, `smtp`, `app`, `api`, `hub`,
//! `admin`, `support`, `help`, `info`, `abuse`, `postmaster`,
//! `noreply`). A separate, optional advisory list of paid-tier
//! dictionary words is future-work on the hub side.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::crypto::pq::{MlDsa65PublicKey, MlDsa65Signature};
use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::{ProtocolError, ValidationError};
use crate::types::{FormatVersion, Username};

/// Security-critical reserved-name list. These strings can never
/// be claimed as subdomains regardless of paid-tier policy. Names
/// in this list are typically MX / web / management surfaces an
/// operator might want to reserve at the apex.
const RESERVED: &[&str] = &[
    "www",
    "mail",
    // Note: `mx` is implicitly unclaimable via the 3-char min-
    // length check below; it would be redundant here.
    "smtp",
    "app",
    "api",
    "hub",
    "admin",
    "support",
    "help",
    "info",
    "abuse",
    "postmaster",
    "noreply",
];

/// Whether `s` is a security-critical reserved subdomain. Match
/// is case-insensitive (caller's input is lowered first).
#[must_use]
pub fn is_reserved_subdomain(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    RESERVED.contains(&lower.as_str())
}

/// Advisory policy classification for a parsed [`Subdomain`].
/// Every claim today is [`SubdomainPolicy::Free`]; paid-tier
/// mechanics and the dictionary list are future-work on the hub.
/// Kept here as a typed seam so the CLI can surface the eventual
/// paid-tier upsell flow without further API churn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubdomainPolicy {
    Free,
    PaidTierRequired,
}

/// Returns the policy class for `s`. Always [`Free`] in MVP.
///
/// [`Free`]: SubdomainPolicy::Free
#[must_use]
pub fn classify(_sub: &Subdomain) -> SubdomainPolicy {
    // TODO: future-work — wire an advisory hub-side dictionary
    // list for paid-tier names. Today every accepted subdomain is
    // free.
    SubdomainPolicy::Free
}

/// User-claimed mail subdomain. Format: lowercase ASCII
/// alphanumeric + `-` + `_`, length 3–32 (DNS-safe by
/// construction). Holds only the local part — combine with a
/// base domain via [`full_domain`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Subdomain(String);

impl Subdomain {
    /// Parse a subdomain from raw user input. Trims surrounding
    /// whitespace and ASCII-lowercases.
    ///
    /// Format rules (kept identical to [`Username`] so subdomain
    /// + username can be compared meaningfully):
    /// - Length 3–32 ASCII characters (post-trim, post-lowercase).
    /// - Allowed character class: `[a-z0-9_-]`.
    /// - MUST NOT match the reserved-names list.
    ///
    /// **Does not** check against a username — for the privacy
    /// invariant use [`parse_against_username`].
    ///
    /// # Errors
    ///
    /// `ValidationError::SubdomainInvalid` for format / length /
    /// character violations; `ValidationError::SubdomainReserved`
    /// for the reserved-names list.
    ///
    /// [`parse_against_username`]: Self::parse_against_username
    pub fn parse(input: &str) -> Result<Self, ValidationError> {
        let lower = input.trim().to_ascii_lowercase();
        if lower.len() < 3 {
            return Err(ValidationError::SubdomainInvalid(
                "too short (min 3)".into(),
            ));
        }
        if lower.len() > 32 {
            return Err(ValidationError::SubdomainInvalid(
                "too long (max 32)".into(),
            ));
        }
        for (i, c) in lower.chars().enumerate() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
                return Err(ValidationError::SubdomainInvalid(format!(
                    "illegal character at position {i}: {c:?}"
                )));
            }
        }
        if is_reserved_subdomain(&lower) {
            return Err(ValidationError::SubdomainReserved(lower));
        }
        Ok(Self(lower))
    }

    /// Parse a subdomain AND enforce the privacy invariant
    /// `subdomain != username` client-side.
    ///
    /// Both inputs are NFC + ASCII-lowercased before comparison
    /// (the `Username` newtype already lowercases on construction;
    /// this function lowercases the subdomain input the same way).
    ///
    /// # Errors
    ///
    /// All errors from [`parse`] plus
    /// `ValidationError::SubdomainEqualsUsername` when the
    /// normalised strings match.
    ///
    /// [`parse`]: Self::parse
    pub fn parse_against_username(
        input: &str,
        username: &Username,
    ) -> Result<Self, ValidationError> {
        let sub = Self::parse(input)?;
        if sub.0 == username.as_str() {
            return Err(ValidationError::SubdomainEqualsUsername);
        }
        Ok(sub)
    }

    /// Borrow the local-part string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Subdomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Join a [`Subdomain`] with its configured base domain to
/// produce the full DNS name (e.g. `inbox-demo` + `vito.gg` →
/// `inbox-demo.vito.gg`).
///
/// The base is passed in unmodified — caller is responsible for
/// normalising the base before calling (production base domains
/// are configured at hub deploy time and don't need
/// normalisation per-call).
#[must_use]
pub fn full_domain(sub: &Subdomain, base: &str) -> String {
    format!("{}.{base}", sub.0)
}

/// Signed user-side claim of a subdomain on a configured base
/// domain. The hub stores this verbatim for verification + public
/// lookups; the user's vault writes a corresponding `Domain`
/// record to the snapshot chain so the claim survives hub loss.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubdomainClaim {
    pub format_version: FormatVersion,
    pub subdomain: Subdomain,
    pub base_domain: String,
    pub user_identity_pubkey: MlDsa65PublicKey,
    pub claimed_at_ms: u64,
    pub sig_user: MlDsa65Signature,
}

impl SubdomainClaim {
    /// Deterministic byte representation that
    /// [`SubdomainClaim::sig_user`] signs over. Excludes the
    /// signature itself so the recipient can recompute and
    /// verify.
    ///
    /// Layout: `b"vitonomi/subdomain_claim/v1" ||
    /// format_version(1) || subdomain_len(varint le) ||
    /// subdomain || base_domain_len(varint le) || base_domain ||
    /// pubkey_len(varint le) || pubkey || claimed_at_ms(8 le)`.
    ///
    /// # Errors
    ///
    /// Currently infallible; signature returns `Result` for
    /// future-proofing if a length cap is added.
    pub fn to_signed_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = Vec::with_capacity(
            32 + 1 + self.subdomain.as_str().len() + self.base_domain.len() + 8,
        );
        out.extend_from_slice(b"vitonomi/subdomain_claim/v1");
        out.push(self.format_version.as_u8());
        write_varint(&mut out, self.subdomain.as_str().len() as u64);
        out.extend_from_slice(self.subdomain.as_str().as_bytes());
        write_varint(&mut out, self.base_domain.len() as u64);
        out.extend_from_slice(self.base_domain.as_bytes());
        write_varint(&mut out, self.user_identity_pubkey.0.len() as u64);
        out.extend_from_slice(&self.user_identity_pubkey.0);
        out.extend_from_slice(&self.claimed_at_ms.to_le_bytes());
        Ok(out)
    }

    /// Verify the embedded `sig_user` against
    /// `user_identity_pubkey` and the deterministic
    /// [`Self::to_signed_bytes`] message.
    ///
    /// # Errors
    ///
    /// `ProtocolError::Cbor` if `to_signed_bytes` fails;
    /// `ProtocolError::Malformed` if the signature does not
    /// verify.
    pub fn verify(&self) -> Result<(), ProtocolError> {
        let msg = self.to_signed_bytes()?;
        crate::crypto::pq::ml_dsa_65_verify(&self.user_identity_pubkey, &self.sig_user, &msg)
            .map_err(|_| ProtocolError::Malformed("subdomain_claim signature invalid".into()))?;
        Ok(())
    }

    /// Encode the full claim record as deterministic CBOR.
    ///
    /// # Errors
    ///
    /// `ProtocolError::Cbor` on encode failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        cbor_to_vec(self)
    }

    /// Decode a CBOR-encoded claim record.
    ///
    /// # Errors
    ///
    /// `ProtocolError::Cbor` on decode failure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        cbor_from_slice(bytes)
    }
}

/// LEB128 (protobuf-style) varint, the same encoding the rest of
/// `vitonomi-core::encoding` uses for length prefixes.
fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::{ml_dsa_65_keypair, ml_dsa_65_sign};

    fn user(name: &str) -> Username {
        Username::parse(name).unwrap()
    }

    // ── Format / character class ──────────────────────────────

    #[test]
    fn subdomain_accepts_typical_inputs() {
        assert_eq!(Subdomain::parse("inbox").unwrap().as_str(), "inbox");
        assert_eq!(Subdomain::parse("inbox-demo").unwrap().as_str(), "inbox-demo");
        assert_eq!(Subdomain::parse("pi_node").unwrap().as_str(), "pi_node");
        assert_eq!(Subdomain::parse("a1b2-c3").unwrap().as_str(), "a1b2-c3");
    }

    #[test]
    fn subdomain_lowercases_and_trims() {
        assert_eq!(Subdomain::parse("INBOX").unwrap().as_str(), "inbox");
        assert_eq!(Subdomain::parse("  Inbox-Demo  ").unwrap().as_str(), "inbox-demo");
    }

    #[test]
    fn subdomain_rejects_too_short_and_too_long() {
        assert!(matches!(
            Subdomain::parse("ab"),
            Err(ValidationError::SubdomainInvalid(_))
        ));
        assert!(matches!(
            Subdomain::parse(""),
            Err(ValidationError::SubdomainInvalid(_))
        ));
        let s: String = "a".repeat(33);
        assert!(matches!(
            Subdomain::parse(&s),
            Err(ValidationError::SubdomainInvalid(_))
        ));
    }

    #[test]
    fn subdomain_rejects_illegal_chars() {
        for bad in [
            "inbox.demo", // dot is invalid in the local part
            "inbox demo",
            "inbox@demo",
            "inbox/demo",
            "inböx",
            "почта",
        ] {
            assert!(
                matches!(
                    Subdomain::parse(bad),
                    Err(ValidationError::SubdomainInvalid(_))
                ),
                "expected rejection for {bad:?}"
            );
        }
    }

    // ── Reserved names ────────────────────────────────────────

    #[test]
    fn subdomain_rejects_reserved_names() {
        for r in RESERVED {
            assert!(
                matches!(
                    Subdomain::parse(r),
                    Err(ValidationError::SubdomainReserved(_))
                ),
                "expected reserved rejection for {r:?}"
            );
        }
    }

    #[test]
    fn subdomain_rejects_reserved_names_case_insensitive() {
        assert!(matches!(
            Subdomain::parse("ADMIN"),
            Err(ValidationError::SubdomainReserved(_))
        ));
    }

    #[test]
    fn is_reserved_helper_matches_parse_rejection() {
        assert!(is_reserved_subdomain("admin"));
        assert!(is_reserved_subdomain("ADMIN"));
        assert!(!is_reserved_subdomain("inbox"));
    }

    // ── Privacy invariant: subdomain != username ──────────────

    #[test]
    fn subdomain_rejects_when_equals_username() {
        let alice = user("alice");
        let err = Subdomain::parse_against_username("alice", &alice).unwrap_err();
        assert!(matches!(err, ValidationError::SubdomainEqualsUsername));
    }

    #[test]
    fn subdomain_rejects_when_equals_username_case_normalised() {
        let alice = user("alice");
        // ALICE → lowered → "alice" → equals username
        let err = Subdomain::parse_against_username("ALICE", &alice).unwrap_err();
        assert!(matches!(err, ValidationError::SubdomainEqualsUsername));
    }

    #[test]
    fn subdomain_accepts_when_distinct_from_username() {
        let alice = user("alice");
        let sub = Subdomain::parse_against_username("inbox-alice", &alice).unwrap();
        assert_eq!(sub.as_str(), "inbox-alice");
    }

    // ── Policy classification ─────────────────────────────────

    #[test]
    fn subdomain_dictionary_words_flagged_paid_tier() {
        // Every accepted subdomain is Free today. An advisory
        // hub-side dictionary list is future-work; this test pins
        // the contract that the classifier exists and returns
        // Free for everything that parses.
        let sub = Subdomain::parse("inbox-demo").unwrap();
        assert_eq!(classify(&sub), SubdomainPolicy::Free);
    }

    // ── full_domain helper ────────────────────────────────────

    #[test]
    fn full_domain_joins_subdomain_and_base() {
        let sub = Subdomain::parse("inbox-demo").unwrap();
        assert_eq!(full_domain(&sub, "vito.gg"), "inbox-demo.vito.gg");
    }

    // ── SubdomainClaim CBOR + signature round-trip ────────────

    fn make_claim(subdomain: &str, base: &str) -> (SubdomainClaim, MlDsa65PublicKey) {
        let kp = ml_dsa_65_keypair().unwrap();
        let sub = Subdomain::parse(subdomain).unwrap();
        let mut claim = SubdomainClaim {
            format_version: FormatVersion::V1,
            subdomain: sub,
            base_domain: base.into(),
            user_identity_pubkey: kp.public.clone(),
            claimed_at_ms: 1_700_000_000_000,
            // placeholder; overwritten below
            sig_user: MlDsa65Signature(vec![]),
        };
        let msg = claim.to_signed_bytes().unwrap();
        let sig = ml_dsa_65_sign(&kp.secret, &msg).unwrap();
        claim.sig_user = sig;
        (claim, kp.public)
    }

    #[test]
    fn subdomain_claim_round_trip_via_cbor() {
        let (claim, _) = make_claim("inbox-demo", "vito.gg");
        let bytes = claim.to_bytes().unwrap();
        let back = SubdomainClaim::from_bytes(&bytes).unwrap();
        assert_eq!(back, claim);
    }

    #[test]
    fn subdomain_claim_signature_verifies() {
        let (claim, _) = make_claim("inbox-demo", "vito.gg");
        claim.verify().expect("freshly-signed claim verifies");
    }

    #[test]
    fn subdomain_claim_rejects_signature_under_wrong_pubkey() {
        let (mut claim, _) = make_claim("inbox-demo", "vito.gg");
        let other = ml_dsa_65_keypair().unwrap();
        // Re-sign WITHOUT changing the embedded pubkey: claim is
        // now self-inconsistent (pubkey doesn't match signer).
        let msg = claim.to_signed_bytes().unwrap();
        claim.sig_user = ml_dsa_65_sign(&other.secret, &msg).unwrap();
        assert!(claim.verify().is_err());
    }

    #[test]
    fn subdomain_claim_signed_bytes_change_with_subdomain() {
        let (a, _) = make_claim("inbox-demo", "vito.gg");
        let mut b = a.clone();
        b.subdomain = Subdomain::parse("inbox-other").unwrap();
        assert_ne!(a.to_signed_bytes().unwrap(), b.to_signed_bytes().unwrap());
    }

    #[test]
    fn subdomain_claim_signed_bytes_change_with_base_domain() {
        let (a, _) = make_claim("inbox-demo", "vito.gg");
        let mut b = a.clone();
        b.base_domain = "example.com".into();
        assert_ne!(a.to_signed_bytes().unwrap(), b.to_signed_bytes().unwrap());
    }
}
