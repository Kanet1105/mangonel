use crate::{
    routes::{
        error::ApiError,
        tfa::{register::RegisterRequest, AppState},
    },
    services::tfa::TFAResponse,
};
use axum::{extract::State, response::IntoResponse, Json};
use serde::Serialize;

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
