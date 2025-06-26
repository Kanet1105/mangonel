use axum::Json;
use lettre::message::Mailbox;
use lettre::transport::smtp::response::Response;
use lettre::transport::smtp::Error;
use lettre::Message;
use lettre::SmtpTransport;
use lettre::Transport;
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::{collections::HashMap, time::Instant};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use uuid::Uuid;

pub const TFA_CODE_TIMEOUT: u64 = 90;
pub const KEY_TIMEOUT: u64 = 600;
pub const REQUEST_LIMIT: usize = 5;

pub type TFACode = u32;

#[derive(Clone)]
pub struct TFAService(UnboundedSender<TFARequest>);

impl TFAService {
    pub fn run() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let storage = TFAStorage {
            receiver,
            storage: HashMap::with_capacity(1000),
        };
        tokio::spawn(storage);
        TFAService(sender)
    }

    pub fn register(&self, key: impl Into<TFAKey>) -> UnboundedReceiver<TFAResponse> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let request = TFARequest::Register(key.into(), sender);
        self.0.send(request).unwrap();
        receiver
    }

    pub fn deregister(&self, key: impl Into<TFAKey>) -> UnboundedReceiver<TFAResponse> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let request = TFARequest::Deregister(key.into(), sender);
        self.0.send(request).unwrap();
        receiver
    }

    pub fn verify_and_issue_token(
        &self,
        key: impl Into<TFAKey>,
        code: u32,
    ) -> UnboundedReceiver<TFAResponse> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let request = TFARequest::VerifyAndIssueToken(key.into(), code, sender);
        self.0.send(request).unwrap();
        receiver
    }
}

#[derive(Clone, Debug)]
pub enum TFARequest {
    Register(TFAKey, UnboundedSender<TFAResponse>),
    Deregister(TFAKey, UnboundedSender<TFAResponse>),
    VerifyAndIssueToken(TFAKey, TFACode, UnboundedSender<TFAResponse>),
}

#[derive(Clone, Debug)]
pub enum TFAResponse {
    Registered(u32),
    CodeExpired,
    Deregistered,
    Token(String),
    TooManyRegisterRequests(u64),
    TooManyGetTokenRequests,
}

pub struct TFAStorage {
    receiver: UnboundedReceiver<TFARequest>,
    storage: HashMap<TFAKey, TFAValue>,
}

impl Future for TFAStorage {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.receiver.poll_recv(cx) {
            Poll::Ready(request) => {
                if let Some(request) = request {
                    this.handle_request(request);
                }
            }
            Poll::Pending => {}
        }

        this.flush_expired_keys();
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl TFAStorage {
    fn handle_request(&mut self, request: TFARequest) {
        match request {
            TFARequest::Register(key, sender) => {
                let code = if let Some(val) = self.storage.get_mut(&key) {
                    if val.too_many_register_requests() {
                        let remaining_cooldown =
                            KEY_TIMEOUT.saturating_sub(val.time_elapsed_since_creation());

                        if remaining_cooldown != 0 {
                            sender
                                .send(TFAResponse::TooManyRegisterRequests(remaining_cooldown))
                                .unwrap();

                            return;
                        }

                        val.log.clear();
                        val.token = None;
                        val.token_version = TokenVersion::None;
                    }

                    val.log.push(Instant::now());
                    val.code = rand::random_range(0..1_000_000);
                    val.code
                } else {
                    let new_value = TFAValue::new();
                    let code = new_value.code;
                    self.storage.insert(key.clone(), new_value);

                    code
                };

                sender.send(TFAResponse::Registered(code)).unwrap();
            }
            TFARequest::Deregister(key, sender) => {
                self.storage.remove(&key);
                sender.send(TFAResponse::Deregistered).unwrap();
            }
            TFARequest::VerifyAndIssueToken(key, tfa_code, sender) => {
                if let Some(value) = self.storage.get_mut(&key) {
                    if value.code() != tfa_code {
                        return sender.send(TFAResponse::CodeExpired).unwrap();
                    }

                    if value.too_many_register_requests() {
                        return sender
                            .send(TFAResponse::TooManyRegisterRequests(KEY_TIMEOUT))
                            .unwrap();
                    }

                    if value.is_code_expired() {
                        sender.send(TFAResponse::CodeExpired).unwrap();
                        return;
                    }

                    if let Ok(token_version) = value.token_version.next_version() {
                        if token_version == TokenVersion::V1 {
                            value.set_token(Uuid::new_v4().to_string());
                        }
                    } else {
                        return sender.send(TFAResponse::TooManyGetTokenRequests).unwrap();
                    }

                    sender
                        .send(TFAResponse::Token(value.token().cloned().unwrap()))
                        .unwrap();
                } else {
                    sender.send(TFAResponse::CodeExpired).unwrap();
                }
            }
        }
    }

    fn flush_expired_keys(&mut self) {
        self.storage.retain(|_key, value| !value.is_code_expired());
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TFAKey(String);

impl From<String> for TFAKey {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug)]
pub struct TFAValue {
    log: Vec<Instant>,
    code: u32,
    token: Option<String>,
    token_version: TokenVersion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum TokenVersion {
    #[default]
    None = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

impl TokenVersion {
    fn next_version(&mut self) -> Result<Self, ()> {
        let next_version = match self {
            TokenVersion::None => TokenVersion::V1,
            TokenVersion::V1 => TokenVersion::V2,
            TokenVersion::V2 => TokenVersion::V3,
            TokenVersion::V3 => TokenVersion::V4,
            TokenVersion::V4 => TokenVersion::V5,
            TokenVersion::V5 => return Err(()),
        };

        *self = next_version;

        Ok(next_version)
    }
}

impl Default for TFAValue {
    fn default() -> Self {
        Self {
            log: Vec::with_capacity(6),
            code: rand::random_range(0..1_000_000),
            token_version: TokenVersion::None,
            token: None,
        }
    }
}

impl TFAValue {
    pub fn new() -> Self {
        let mut log = Vec::with_capacity(6);
        log.push(Instant::now());
        Self {
            log,
            code: rand::random_range(0..1_000_000),
            token_version: TokenVersion::None,
            token: None,
        }
    }

    pub fn is_code_expired(&self) -> bool {
        let elapsed = self.time_elapsed_sice_last_request();
        elapsed > TFA_CODE_TIMEOUT
    }

    pub fn too_many_register_requests(&self) -> bool {
        self.log.len() > 5
    }

    pub fn time_elapsed_sice_last_request(&self) -> u64 {
        (Instant::now() - *self.log.last().unwrap()).as_secs()
    }

    pub fn time_elapsed_since_creation(&self) -> u64 {
        (Instant::now() - self.log[0]).as_secs()
    }

    pub fn code(&self) -> u32 {
        self.code
    }

    pub fn token(&self) -> Option<&String> {
        self.token.as_ref()
    }

    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }
}

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
