//! Wire types for the subdomain-claim surface.
//!
//! The hub stores `(base_domain, subdomain) → user record`. The
//! claim itself ([`crate::types::subdomain::SubdomainClaim`]) is
//! carried in `POST /v1/subdomains` as the body; the response is
//! empty on success.

use serde::{Deserialize, Serialize};

use crate::crypto::pq::MlDsa65PublicKey;
use crate::types::subdomain::Subdomain;

/// Public lookup result for `GET /v1/subdomains/{base}/{sub}`.
/// Returned to anyone (no auth) so an mx relay or client can resolve
/// "who owns this namespace?" without holding a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubdomainDirectoryEntry {
    pub subdomain: Subdomain,
    pub base_domain: String,
    pub user_identity_pubkey: MlDsa65PublicKey,
    /// Pointer the alias-directory lookups key under for this
    /// user's namespace. Opaque to callers; client treats it as
    /// `namespace = format!("{subdomain}.{base_domain}")` until
    /// the hub decides to indirect.
    pub alias_kem_directory_pointer: String,
}

/// Public listing of base domains the hub allows subdomain
/// claims under. Hosted vitonomi serves `["vito.gg"]`;
/// self-hosters configure their own. Returned by
/// `GET /v1/managed-base-domains`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ManagedBaseDomains {
    pub bases: Vec<String>,
}
