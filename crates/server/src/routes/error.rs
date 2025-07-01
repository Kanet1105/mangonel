use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(tag = "error", content = "message")]
pub enum ApiError {
    Unauthorized(Option<String>),
    TooMany,
    NotFound,
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::TooMany => StatusCode::TOO_MANY_REQUESTS,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}
