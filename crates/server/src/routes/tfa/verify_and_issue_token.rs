use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::routes::tfa::AppState;
use crate::services::tfa::{TFAError, TFAResponse};

#[derive(Serialize, Deserialize)]
pub struct VerifyCodeRequest {
    pub email: String,
    pub code: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum VerifyCodeResponse {
    Ok {
        token: String,
    },
    Error {
        kind: ErrorKind,
        message: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
pub enum ErrorKind {
    TooManyRequests,
    NotFound,
    InvalidCode,
    Internal,
}

impl IntoResponse for VerifyCodeResponse {
    fn into_response(self) -> Response {
        match self {
            VerifyCodeResponse::Ok { token } => {
                let body = Json(VerifyCodeResponse::Ok { token });
                (StatusCode::OK, body).into_response()
            }
            VerifyCodeResponse::Error { kind, message } => {
                let status = match kind {
                    ErrorKind::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
                    ErrorKind::NotFound => StatusCode::NOT_FOUND,
                    ErrorKind::InvalidCode => StatusCode::UNAUTHORIZED,
                    ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
                };
                let body = Json(VerifyCodeResponse::Error { kind, message });
                (status, body).into_response()
            }
        }
    }
}

pub async fn verify_and_issue_token(
    State(state): State<AppState>,
    Json(payload): Json<VerifyCodeRequest>,
) -> impl IntoResponse {
    let mut receiver = state
        .tfa_service
        .verify_and_issue_token(payload.email, payload.code);

    match receiver.recv().await {
        Some(TFAResponse::Token(token)) => (StatusCode::OK, Json(VerifyCodeResponse::Ok { token })),
        Some(TFAResponse::Error(TFAError::InvalidCode)) => (
            StatusCode::UNAUTHORIZED,
            Json(VerifyCodeResponse::Error {
                kind: ErrorKind::InvalidCode,
                message: None,
            }),
        ),
        Some(TFAResponse::Error(TFAError::NotFound)) => (
            StatusCode::NOT_FOUND,
            Json(VerifyCodeResponse::Error {
                kind: ErrorKind::NotFound,
                message: None,
            }),
        ),
        Some(TFAResponse::Error(TFAError::TooManyGetTokenRequests)) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(VerifyCodeResponse::Error {
                kind: ErrorKind::TooManyRequests,
                message: None,
            }),
        ),
        Some(TFAResponse::Error(TFAError::CodeExpired)) => (
            StatusCode::UNAUTHORIZED,
            Json(VerifyCodeResponse::Error {
                kind: ErrorKind::InvalidCode,
                message: Some("Code expired".to_string()),
            }),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(VerifyCodeResponse::Error {
                kind: ErrorKind::Internal,
                message: None,
            }),
        ),
    }
}
