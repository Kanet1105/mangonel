use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::routes::tfa::register::RegisterSuccess;
use crate::services::auth::AuthError;
use crate::services::tfa::TFAError;

#[derive(Debug, Serialize)]
#[serde(tag = "error", content = "message")]
pub enum ApiError {
    Unauthorized(Option<String>),
    TooManyRegisterRequests(Option<u16>),
    TooManyGetTokenRequests,
    NotFound,
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::TooManyRegisterRequests(_cooldown) => {
                if let Some(cooldown) = _cooldown {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(RegisterSuccess {
                            cooldown: Some(cooldown),
                        }),
                    )
                        .into_response();
                } else {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(RegisterSuccess { cooldown: None }),
                    )
                        .into_response();
                }
            }
            ApiError::TooManyGetTokenRequests => StatusCode::TOO_MANY_REQUESTS,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::InvalidCredentials => {
                ApiError::Unauthorized(Some("Invalid credentials".into()))
            }
            AuthError::UserAlreadyExists => {
                ApiError::Unauthorized(Some("User already exists".into()))
            }
            AuthError::UserNotFound => ApiError::NotFound,
            AuthError::UserLocked => ApiError::Unauthorized(Some("Account locked".into())),
            _ => ApiError::Internal,
        }
    }
}

impl From<TFAError> for ApiError {
    fn from(e: TFAError) -> Self {
        use TFAError::*;
        match e {
            InvalidCode => ApiError::Unauthorized(None),
            CodeExpired => ApiError::Unauthorized(Some("Code expired".into())),
            TooManyGetTokenRequests => ApiError::TooManyGetTokenRequests,
            TooManyRegisterRequests(times) => ApiError::TooManyRegisterRequests(Some(times as u16)),
            NotFound => ApiError::NotFound,
            _ => ApiError::Internal,
        }
    }
}
