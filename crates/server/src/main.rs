use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{routing::post, Json, Router};
use lazy_static::lazy_static;
use lettre::{message::Mailbox, Message, SmtpTransport, Transport};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

lazy_static! {
    static ref SERVER_CODE: Mutex<Option<String>> = Mutex::new(None);
    static ref REQUEST_LOG: Mutex<HashMap<String, Vec<Instant>>> = Mutex::new(HashMap::new());
    static ref AUTH_TOKEN: Mutex<Option<String>> = Mutex::new(None);
}

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/api/send_code", post(send_code))
        .route("/api/verify_code", post(verify_code))
        .layer(cors);
    println!("Server started at http://localhost:3000");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[derive(Deserialize)]
struct EmailRequest {
    to: String,
}

#[derive(Deserialize)]
struct EmailCredential {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct SendCodeResponse {
    status: String,
    cooldown: Option<u16>,
}

async fn send_code(Json(payload): Json<EmailRequest>) -> Json<SendCodeResponse> {
    let now = Instant::now();
    let mut log = REQUEST_LOG.lock().unwrap();

    let entry = log.entry(payload.to.clone()).or_default();
    entry.retain(|&time| now.duration_since(time) <= Duration::from_secs(300));
    println!("entry: {:?}", entry);

    if entry.len() >= 5 {
        let earliest = entry.first().unwrap();
        let elapsed = now.duration_since(*earliest).as_secs() as u16;
        let remaining = 300u16.saturating_sub(elapsed);

        return Json(SendCodeResponse {
            status: "rate limited".into(),
            cooldown: Some(remaining),
        });
    }

    entry.push(now);
    drop(log);

    let code = format!("{:06}", rand::rng().random_range(0..1_000_000));

    {
        let mut lock = SERVER_CODE.lock().unwrap();
        *lock = Some(code.clone());
    }

    tokio::spawn(async {
        sleep(Duration::from_secs(180)).await;
        let mut lock = SERVER_CODE.lock().unwrap();
        *lock = None;
        println!("2FA code expired");
    });

    let email = Message::builder()
        .from(
            "Mangonel <noreply@mangonel.com>"
                .parse::<Mailbox>()
                .unwrap(),
        )
        .to(payload.to.parse::<Mailbox>().unwrap())
        .subject("Your 2FA Code")
        .body(format!("Your 2FA code is: {}", code))
        .unwrap();

    let email_credential_string = std::fs::read_to_string("email_credentials.json")
        .expect("Failed to read email credentials");
    let email_credential: EmailCredential =
        serde_json::from_str(&email_credential_string).expect("Failed to parse email credentials");

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(lettre::transport::smtp::authentication::Credentials::new(
            email_credential.email,
            email_credential.password,
        ))
        .build();

    match mailer.send(&email) {
        Ok(_) => Json(SendCodeResponse {
            status: "sent".into(),
            cooldown: None,
        }),
        Err(e) => {
            eprintln!("Could not send email: {:?}", e);
            Json(SendCodeResponse {
                status: "error".into(),
                cooldown: None,
            })
        }
    }
}

#[derive(Deserialize)]
struct VerifyRequest {
    code: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    status: String,
    token: Option<String>,
}

async fn verify_code(Json(payload): Json<VerifyRequest>) -> Json<VerifyResponse> {
    let stored = SERVER_CODE.lock().unwrap();
    if let Some(code) = stored.as_ref() {
        if &payload.code == code {
            let token = Uuid::new_v4().to_string();
            *AUTH_TOKEN.lock().unwrap() = Some(token.clone());

            return Json(VerifyResponse {
                status: "ok".into(),
                token: Some(token),
            });
        }
    } else {
        *AUTH_TOKEN.lock().unwrap() = None;
    }
    Json(VerifyResponse {
        status: "error".into(),
        token: None,
    })
}
