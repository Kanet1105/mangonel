use axum::response::IntoResponse;
use axum::Json;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    status: String,
    email: Option<String>,
}

pub async fn login(Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    match crate::services::auth::login(&payload.email, &payload.password) {
        Ok(email) => {
            if !is_tfa_server_healthy().await {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(LoginResponse {
                        status: "Failure".into(),
                        email: None,
                    }),
                );
            }

            (
                StatusCode::OK,
                Json(LoginResponse {
                    status: "Ok".into(),
                    email: Some(email),
                }),
            )
        }
        Err(_e) => (
            StatusCode::UNAUTHORIZED,
            Json(LoginResponse {
                status: "Failure".into(),
                email: None,
            }),
        ),
    }
}

async fn is_tfa_server_healthy() -> bool {
    match reqwest::get("http://localhost:3002/health").await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}
