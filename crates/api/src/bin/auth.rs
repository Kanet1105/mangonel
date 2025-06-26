use api::routes::auth::auth_router;
use api::routes::common::health_router;
use tower_http::cors::{Any, CorsLayer};

const AUTH_SERVER_BINDING: &str = "0.0.0.0:3001";

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    let app = auth_router().merge(health_router()).layer(cors);

    println!("Auth server listening on http://localhost:3001");

    let listener = tokio::net::TcpListener::bind(AUTH_SERVER_BINDING)
        .await
        .unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
