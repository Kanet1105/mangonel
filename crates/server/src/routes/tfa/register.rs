use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::routes::error::ApiError;
use crate::routes::tfa::AppState;
use crate::services::tfa::{send_email_code, EmailRequest, TFAResponse};

#[derive(Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
}

#[derive(Serialize, Default)]
pub struct RegisterSuccess {
    pub cooldown: Option<u16>,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let mut receiver = state.tfa_service.register(payload.email.clone());
    match receiver.recv().await {
        Some(TFAResponse::Registered(code)) => {
            tokio::spawn(async move {
                let _ = send_email_code(Json(EmailRequest {
                    to: payload.email.clone(),
                    code: code.to_string(),
                }))
                .await;
            });

            Ok(Json(RegisterSuccess { cooldown: None }))
        }
        Some(TFAResponse::Error(error)) => Err(ApiError::from(error)),
        _ => Err(ApiError::Internal),
    }
}
