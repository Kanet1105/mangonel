use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

pub fn health_router() -> Router {
    Router::new().route("/health", get(health_handler))
}
