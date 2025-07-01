use std::sync::Arc;

use axum::routing::post;
use axum::Router;

use crate::routes::tfa::deregister::deregister;
use crate::routes::tfa::register::register;
use crate::routes::tfa::verify_and_issue_token::verify_and_issue_token;
use crate::services::tfa::TFAService;

pub mod deregister;
pub mod register;
pub mod verify_and_issue_token;

#[derive(Clone)]
pub struct AppState {
    pub tfa_service: Arc<TFAService>,
}

pub fn tfa_router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/deregister", post(deregister))
        .route("/verify", post(verify_and_issue_token))
}
