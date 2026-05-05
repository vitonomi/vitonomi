//! Bearer-token extractor used by every authenticated route. The
//! actual session validation happens in the `HubControlPlane`
//! implementation; this just plucks the token out of the
//! `Authorization` header.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use vitonomi_core::types::SessionToken;

/// Extracts a `SessionToken` from the `Authorization: Bearer <token>`
/// header.
pub struct BearerSession(pub SessionToken);

impl<S> FromRequestParts<S> for BearerSession
where
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .ok_or(AuthRejection::Missing)?
            .to_str()
            .map_err(|_| AuthRejection::Malformed)?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(AuthRejection::Malformed)?
            .trim();
        if token.is_empty() {
            return Err(AuthRejection::Malformed);
        }
        Ok(Self(SessionToken(token.to_string())))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AuthRejection {
    Missing,
    Malformed,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "code": "auth.token_missing",
            "message": match self {
                AuthRejection::Missing => "missing Authorization header",
                AuthRejection::Malformed => "malformed Authorization header (expected `Bearer <token>`)",
            },
        }));
        (StatusCode::UNAUTHORIZED, body).into_response()
    }
}
