use axum::routing::post;
use axum::Router;

use crate::routes::auth::login::login;

pub mod login;

pub fn auth_router() -> Router {
    Router::new().route("/login", post(login))
}
