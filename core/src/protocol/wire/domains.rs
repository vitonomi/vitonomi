//! Wire types for the Phase 7 custom-domain DNS-verify surface.

use serde::{Deserialize, Serialize};

/// Status of a user-owned custom domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DomainStatus {
    /// Hub has issued a challenge; user must publish DNS records.
    Pending,
    /// DNS records resolved correctly; ready to be activated.
    Verified,
    /// Active — the relay accepts mail for this domain.
    Active,
    /// Operator / user disabled. Aliases remain but reject mail.
    Disabled,
}

/// Returned by `POST /v1/domains` — the TXT + MX records the
/// user must publish at their DNS provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainChallenge {
    /// The string the user must publish in a TXT record at
    /// `_vitonomi.<domain>` (e.g. base64url(32 random bytes)).
    pub txt_record_value: String,
    /// The MX target the user must point their domain to.
    pub required_mx_target: String,
}

/// Returned by `POST /v1/domains/{domain}/verify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainVerified {
    pub domain: String,
    pub verified_at_ms: u64,
}

/// One row in `GET /v1/domains` (the user's custom-domain list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRecord {
    pub domain: String,
    pub status: DomainStatus,
    pub verified_at_ms: Option<u64>,
}
