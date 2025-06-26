use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::services::tfa::{send_email_code, EmailRequest};
use crate::services::tfa::{TFAResponse, TFAService};

#[derive(Clone)]
pub struct AppState {
    pub tfa_service: Arc<TFAService>,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyCodeRequest {
    pub email: String,
    pub code: u32,
}

#[derive(Serialize, Default)]
pub struct CoolDown {
    cooldown: Option<u16>,
}

#[derive(Serialize)]
pub struct Token {
    token: String,
}

impl From<String> for Token {
    fn from(token: String) -> Self {
        Token { token }
    }
}

impl IntoResponse for CoolDown {
    fn into_response(self) -> axum::response::Response {
        let body = axum::Json(self);
        (StatusCode::OK, body).into_response()
    }
}

impl CoolDown {
    pub fn new(cooldown: u16) -> Self {
        CoolDown {
            cooldown: Some(cooldown),
        }
    }
}

pub fn tfa_router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/deregister", post(deregister))
        .route("/verify", post(verify_and_issue_token))
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

            (StatusCode::OK, CoolDown::default())
        }
        Some(TFAResponse::TooManyRegisterRequests(time_to_wait)) => (
            StatusCode::TOO_MANY_REQUESTS,
            CoolDown::new(time_to_wait as u16),
        ),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, CoolDown::default()),
    }
}

pub async fn deregister(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let mut receiver = state.tfa_service.deregister(payload.email);
    match receiver.recv().await {
        Some(TFAResponse::Deregistered) => (StatusCode::OK, CoolDown::default()),
        _ => (StatusCode::NOT_FOUND, CoolDown::default()),
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
        Some(TFAResponse::Token(token)) => (StatusCode::OK, Json(Token::from(token))),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Token::from("Error".to_string())),
        ),
    }
}
