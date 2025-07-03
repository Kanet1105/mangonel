use crate::{
    routes::tfa::{
        deregister::deregister, register::register, verify_and_issue_token::verify_and_issue_token,
    },
    services::tfa::TFAService,
};
use axum::{routing::post, Router};
use std::sync::Arc;

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
