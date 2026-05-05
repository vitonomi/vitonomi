//! Convert `vitonomi_core` `CoreError`s into HTTP responses with a
//! stable `{ code, message }` envelope per the API spec.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use vitonomi_core::errors::{AuthError, CoreError, CryptoError};

pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

impl From<CoreError> for ApiError {
    fn from(err: CoreError) -> Self {
        let (status, code) = match &err {
            CoreError::Auth(AuthError::InvalidCredentials) => {
                (StatusCode::UNAUTHORIZED, "auth.invalid_credentials")
            }
            CoreError::Auth(AuthError::SessionExpired) => {
                (StatusCode::UNAUTHORIZED, "auth.session_expired")
            }
            CoreError::Auth(AuthError::SessionUnknown) => {
                (StatusCode::UNAUTHORIZED, "auth.session_unknown")
            }
            CoreError::Auth(AuthError::ChallengeExpired) => {
                (StatusCode::UNAUTHORIZED, "auth.challenge_expired")
            }
            CoreError::Auth(AuthError::InviteUsedOrExpired) => {
                (StatusCode::FORBIDDEN, "auth.invite_used_or_expired")
            }
            CoreError::Auth(AuthError::Forbidden) => (StatusCode::FORBIDDEN, "auth.forbidden"),
            CoreError::Auth(AuthError::RateLimited) => {
                (StatusCode::TOO_MANY_REQUESTS, "auth.rate_limited")
            }
            CoreError::Crypto(CryptoError::SignatureInvalid) => {
                (StatusCode::FORBIDDEN, "crypto.signature_invalid")
            }
            CoreError::Crypto(CryptoError::AdminChain(_)) => {
                (StatusCode::FORBIDDEN, "chain.invalid")
            }
            CoreError::Validation(_) => (StatusCode::BAD_REQUEST, "validation.invalid"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        Self {
            status,
            code: code.to_string(),
            message: format!("{err}"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "code": self.code,
            "message": self.message,
        }));
        (self.status, body).into_response()
    }
}
