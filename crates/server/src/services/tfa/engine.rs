use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
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
    Deregistered,
    Token(String),
    Error(TFAError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TFAError {
    TooManyRegisterRequests(u64),
    TooManyGetTokenRequests,
    CodeExpired,
    InvalidCode,
    NotFound,
    Error(String),
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
                    this.handle(request);
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
    fn handle(&mut self, request: TFARequest) {
        match request {
            TFARequest::Register(key, sender) => {
                self.register(key, sender);
            }
            TFARequest::Deregister(key, sender) => {
                self.deregister(key, sender);
            }
            TFARequest::VerifyAndIssueToken(key, tfa_code, sender) => {
                self.verify_and_issue_token(key, tfa_code, sender);
            }
        }
    }

    fn register(&mut self, key: TFAKey, sender: UnboundedSender<TFAResponse>) {
        let code = if let Some(val) = self.storage.get_mut(&key) {
            if val.too_many_register_requests() {
                let remaining_cooldown =
                    KEY_TIMEOUT.saturating_sub(val.time_elapsed_since_creation());

                if remaining_cooldown != 0 {
                    sender
                        .send(TFAResponse::Error(TFAError::TooManyRegisterRequests(
                            remaining_cooldown,
                        )))
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

    fn deregister(&mut self, key: TFAKey, sender: UnboundedSender<TFAResponse>) {
        self.storage.remove(&key);
        sender.send(TFAResponse::Deregistered).unwrap();
    }

    fn verify_and_issue_token(
        &mut self,
        key: TFAKey,
        tfa_code: u32,
        sender: UnboundedSender<TFAResponse>,
    ) {
        if let Some(value) = self.storage.get_mut(&key) {
            if value.code() != tfa_code {
                return sender
                    .send(TFAResponse::Error(TFAError::InvalidCode))
                    .unwrap();
            }

            if value.too_many_register_requests() {
                return sender
                    .send(TFAResponse::Error(TFAError::TooManyRegisterRequests(
                        KEY_TIMEOUT,
                    )))
                    .unwrap();
            }

            if value.is_code_expired() {
                return sender
                    .send(TFAResponse::Error(TFAError::CodeExpired))
                    .unwrap();
            }

            if let Ok(token_version) = value.token_version.next_version() {
                if token_version == TokenVersion::V1 {
                    value.set_token(Uuid::new_v4().to_string());
                }
            } else {
                return sender
                    .send(TFAResponse::Error(TFAError::TooManyGetTokenRequests))
                    .unwrap();
            }

            sender
                .send(TFAResponse::Token(value.token().cloned().unwrap()))
                .unwrap();
        } else {
            sender.send(TFAResponse::Error(TFAError::NotFound)).unwrap();
        }
    }

    fn flush_expired_keys(&mut self) {
        self.storage.retain(|_key, value| {
            if value.time_elapsed_since_creation() > KEY_TIMEOUT {
                false
            } else {
                if value.is_code_expired() {
                    value.token = None;
                    value.token_version = TokenVersion::None;
                }
                true
            }
        });
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
    None,
    V1,
    V2,
    V3,
    V4,
    V5,
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
