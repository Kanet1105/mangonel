use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::routes::tfa::register::{RegisterRequest, RegisterResponse};
use crate::routes::tfa::AppState;
use crate::services::tfa::TFAResponse;

pub async fn deregister(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let mut receiver = state.tfa_service.deregister(payload.email);
    match receiver.recv().await {
        Some(TFAResponse::Deregistered) => (StatusCode::OK, RegisterResponse::default()),
        _ => (StatusCode::NOT_FOUND, RegisterResponse::default()),
    }
}
