use crate::routes::error::ApiError;
use axum::{response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginSuccess {
    pub email: String,
}

pub async fn login(Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    match crate::services::auth::login(&payload.email, &payload.password) {
        Ok(email) => {
            if !is_tfa_server_healthy().await {
                eprintln!("TFA server is not healthy, returning internal error");
                return Err(Json(ApiError::Internal));
            }

            Ok(Json(LoginSuccess {
                email: email.clone(),
            }))
        }
        Err(_e) => Err(Json(ApiError::Unauthorized(Some(
            "Invalid credentials".to_string(),
        )))),
    }
}

async fn is_tfa_server_healthy() -> bool {
    match reqwest::get("http://localhost:3002/health").await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}
