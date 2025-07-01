use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::routes::error::ApiError;
use crate::routes::tfa::register::RegisterRequest;
use crate::routes::tfa::AppState;
use crate::services::tfa::TFAResponse;

#[derive(Serialize)]
pub struct DeregisterSuccess;

pub async fn deregister(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let mut receiver = state.tfa_service.deregister(payload.email);
    match receiver.recv().await {
        Some(TFAResponse::Deregistered) => Ok(Json(DeregisterSuccess)),
        _ => Err(ApiError::Internal),
    }
}
