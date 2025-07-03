use axum::{routing::get, Router};
use reqwest::StatusCode;

async fn health_handler() -> StatusCode {
    StatusCode::OK
}

pub fn health_router() -> Router {
    Router::new().route("/health", get(health_handler))
}
