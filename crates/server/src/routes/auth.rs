use crate::routes::auth::login::login;
use axum::{routing::post, Router};

pub mod login;

pub fn auth_router() -> Router {
    Router::new().route("/login", post(login))
}
