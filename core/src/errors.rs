//! Typed error hierarchy. Every fallible operation in `vitonomi-core`
//! returns one of these enums (or [`CoreError`] for cross-cutting
//! contexts).

use thiserror::Error;

/// Cryptographic-layer failures. Distinct from [`ProtocolError`] so
/// callers can choose to redact the message before logging.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("KDF failure: {0}")]
    Kdf(String),
    #[error("AEAD encryption failed")]
    AeadSeal,
    #[error("AEAD decryption failed (tampered, truncated, or wrong key)")]
    AeadOpen,
    #[error("post-quantum signature verification failed")]
    SignatureInvalid,
    #[error("post-quantum signature operation failed: {0}")]
    Signature(String),
    #[error("post-quantum KEM operation failed: {0}")]
    Kem(String),
    #[error("key blob malformed: {0}")]
    KeyBlob(String),
    #[error("seed phrase invalid: {0}")]
    SeedPhrase(String),
    #[error("admin chain entry malformed or signature invalid: {0}")]
    AdminChain(String),
    #[error("unexpected key length: expected {expected}, got {got}")]
    KeyLength { expected: usize, got: usize },
    #[error("randomness source failed: {0}")]
    Random(String),
}

/// Wire-protocol failures: malformed frames, version mismatches,
/// session-state errors.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("malformed wire frame: {0}")]
    Malformed(String),
    #[error("unsupported format version: got {got}, supported {supported}")]
    UnsupportedVersion { got: u8, supported: u8 },
    #[error("unknown action variant: {0}")]
    UnknownAction(u8),
    #[error("session state error: {0}")]
    SessionState(String),
    #[error("CBOR encoding error: {0}")]
    Cbor(String),
}

/// Auth-layer failures.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("session expired")]
    SessionExpired,
    #[error("session not found or revoked")]
    SessionUnknown,
    #[error("challenge expired or unknown")]
    ChallengeExpired,
    #[error("invite already used or expired")]
    InviteUsedOrExpired,
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("forbidden (insufficient role)")]
    Forbidden,
}

/// Input-validation failures at the type-construction boundary.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("invalid username: {0}")]
    InvalidUsername(String),
    #[error("invalid format version: {0}")]
    InvalidFormatVersion(u8),
    #[error("invalid: {0}")]
    Other(String),
}

/// Network / transport failures (HTTPS / WebSocket / TLS).
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("tls handshake failed: {0}")]
    Tls(String),
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("websocket protocol error: {0}")]
    WebSocket(String),
    #[error("http error: status {status}, message {message}")]
    Http { status: u16, message: String },
}

/// Cross-cutting umbrella error type. Specific layers should prefer
/// the more precise enums above; this exists for aggregation in
/// `Result<T>` aliases at trait boundaries.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Network(#[from] NetworkError),
}
