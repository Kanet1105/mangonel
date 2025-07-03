use axum::Json;
use lettre::{
    message::Mailbox,
    transport::smtp::{response::Response, Error},
    Message, SmtpTransport, Transport,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct EmailRequest {
    pub(crate) to: String,
    pub(crate) code: String,
}

#[derive(Deserialize)]
struct EmailCredential {
    email: String,
    password: String,
}

pub async fn send_email_code(Json(payload): Json<EmailRequest>) -> Result<Response, Error> {
    let body = format!("Your 2FA code is: {}", payload.code);

    let email = Message::builder()
        .from(
            "Mangonel <noreply@mangonel.com>"
                .parse::<Mailbox>()
                .unwrap(),
        )
        .to(payload.to.parse::<Mailbox>().unwrap())
        .subject("Your 2FA Code")
        .body(body)
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

    mailer.send(&email)
}
