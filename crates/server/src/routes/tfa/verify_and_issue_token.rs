use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::routes::error::ApiError;
use crate::routes::tfa::AppState;
use crate::services::tfa::TFAResponse;

#[derive(Serialize, Deserialize)]
pub struct VerifyCodeRequest {
    pub email: String,
    pub code: u32,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyCodeSuccess {
    token: String,
}

pub async fn verify_and_issue_token(
    State(state): State<AppState>,
    Json(payload): Json<VerifyCodeRequest>,
) -> impl IntoResponse {
    let mut receiver = state
        .tfa_service
        .verify_and_issue_token(payload.email, payload.code);

    match receiver.recv().await {
        Some(TFAResponse::Token(token)) => Ok(Json(VerifyCodeSuccess { token })),
        Some(TFAResponse::Error(err)) => Err(ApiError::from(err)),
        _ => Err(ApiError::Internal),
    }
}
