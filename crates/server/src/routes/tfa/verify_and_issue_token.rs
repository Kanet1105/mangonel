use crate::{
    routes::{error::ApiError, tfa::AppState},
    services::tfa::TFAResponse,
};
use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

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
