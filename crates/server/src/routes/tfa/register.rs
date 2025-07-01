use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::routes::tfa::AppState;
use crate::services::tfa::{send_email_code, EmailRequest, TFAError, TFAResponse};

#[derive(Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
}

#[derive(Serialize, Default)]
pub struct RegisterResponse {
    cooldown: Option<u16>,
}

impl IntoResponse for RegisterResponse {
    fn into_response(self) -> axum::response::Response {
        let body = axum::Json(self);
        (StatusCode::OK, body).into_response()
    }
}

impl RegisterResponse {
    pub fn new(cooldown: u16) -> Self {
        RegisterResponse {
            cooldown: Some(cooldown),
        }
    }
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

            (StatusCode::OK, RegisterResponse::default())
        }
        Some(TFAResponse::Error(error)) => match error {
            TFAError::TooManyRegisterRequests(time) => (
                StatusCode::TOO_MANY_REQUESTS,
                RegisterResponse::new(time as u16),
            ),
            TFAError::CodeExpired => (
                StatusCode::NOT_FOUND,
                RegisterResponse { cooldown: Some(0) },
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                RegisterResponse::default(),
            ),
        },
        Some(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            RegisterResponse::default(),
        ),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            RegisterResponse::default(),
        ),
    }
}
