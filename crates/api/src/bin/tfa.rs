use std::sync::Arc;

use api::{
    routes::{
        common::health_router,
        tfa::{tfa_router, AppState},
    },
    services::tfa::TFAService,
};
use tower_http::cors::{Any, CorsLayer};

const TFA_SERVER_BINDING: &str = "0.0.0.0:3002";

#[tokio::main]
async fn main() {
    let tfa_service = TFAService::run();
    let state = AppState {
        tfa_service: Arc::new(tfa_service),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    let app = tfa_router()
        .merge(health_router().with_state(()))
        .with_state(state)
        .layer(cors);

    println!("TFA server listening on http://localhost:3002");

    let listener = tokio::net::TcpListener::bind(TFA_SERVER_BINDING)
        .await
        .unwrap();

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
