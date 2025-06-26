use dioxus::prelude::*;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
enum AuthStatus {
    Idle,
    Sent,
    Sending,
    Timeout,
    Error(String),
    Verified,
}

#[derive(Props, PartialEq, Clone)]
pub struct TwoFactorFormProps {
    pub email: String,
    pub on_success: Callback<()>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthToken(pub String);

#[component]
pub fn TwoFactorForm(props: TwoFactorFormProps) -> Element {
    let mut code_input = use_signal(String::new);
    let countdown: Signal<u16> = use_signal(|| 90);
    let countdown_version: Signal<u64> = use_signal(|| 0);
    let status = use_signal(|| AuthStatus::Idle);
    let mut init = use_signal(|| false);
    let auth_token = use_signal(String::new);
    let email = use_signal(|| props.email);

    use_effect(move || {
        if !*init.read() {
            init.set(true);
            trigger_send_code(email, countdown, status, countdown_version);
        }
    });

    rsx! {
        div {
            style: "display: flex; flex-direction: column; align-items: center; background-color: #f2f2f2; min-height: 100vh;",

            div {
                style: "
                    width: 100%;
                    background-color: #1a1a1a;
                    padding: 20px 0;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
                    display: flex;
                    align-items: center;
                    justify-content: flex-start;
                    padding-left: 40px;
                ",
                h1 {
                    style: "color: white; font-size: 24px; font-weight: bold;",
                    "Mangonel"
                }
            }

            div {
                style: "
                    margin-top: 80px;
                    background-color: white;
                    padding: 32px;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    width: 320px;
                ",

                h2 {
                    style: "font-size: 20px; font-weight: bold; text-align: center; margin-bottom: 24px;",
                    "2FA Authentication"
                }

                p {
                    style: "color: #666; font-size: 14px; margin-bottom: 8px; text-align: center;",
                    "Input the 6-digit code sent to your email."
                }

                input {
                    style: "
                        width: 93%;
                        padding: 10px;
                        margin-bottom: 12px;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 16px;
                        text-align: center;
                        letter-spacing: 0.15em;
                    ",
                    maxlength: "6",
                    value: "{code_input.read()}",
                    oninput: move |e| code_input.set(e.value().to_string())
                }

                button {
                    onclick: on_submit_handler(email, code_input, status, auth_token),
                    style: "
                        width: 100%;
                        padding: 12px;
                        background-color: #007bff;
                        color: white;
                        font-weight: bold;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 16px;
                        margin-bottom: 12px;
                    ",
                    "Confirm"
                }

                button {
                    onclick: on_resend_handler(email, countdown, status, countdown_version),
                    style: "
                        font-size: 14px;
                        color: #007bff;
                        text-decoration: underline;
                        background: none;
                        border: none;
                        cursor: pointer;
                        margin-bottom: 12px;
                    ",
                    "Resend code"
                }

                match &*status.read() {
                    AuthStatus::Sending => rsx!(p { style: "color: #555; padding-left: 5; font-size: 14px;", "Sending..." }),
                    AuthStatus::Sent => rsx!(p { style: "color: #28a745; font-size: 14px;", "Code sent!" }),
                    AuthStatus::Timeout => rsx!(p { style: "color: red; font-size: 14px;", "Timed out. Please resend." }),
                    AuthStatus::Error(msg) => rsx!(p { style: "color: red; font-size: 14px;", "{msg}" }),
                    AuthStatus::Verified => rsx!(
                        div {
                            style: "margin-top: 16px;",
                            p {
                                style: "color: #28a745; font-weight: bold; font-size: 14px; margin-bottom: 8px;",
                                "Authenticated! Here is your access token:"
                            }
                            p {
                                style: "background-color: #f2f2f2; padding: 8px; font-size: 12px; border-radius: 4px; word-break: break-all; font-family: monospace;",
                                "{auth_token.read()}"
                            }
                            button {
                                style: "margin-top: 16px; background-color: #007bff; color: white; font-weight: bold; padding: 12px; border-radius: 4px; width: 100%; border: none; cursor: pointer; font-size: 16px;",
                                onclick: move |_| {
                                    props.on_success.call(());
                                },
                                "Continue"
                            }
                        }
                    ),
                    _ => rsx!(),
                }

                p {
                    style: "text-align: center; color: #666; font-size: 14px; margin-top: 8px;",
                    "Time left: {countdown} seconds"
                }
            }
        }
    }
}

fn trigger_send_code(
    email: Signal<String>,
    countdown: Signal<u16>,
    status: Signal<AuthStatus>,
    countdown_version: Signal<u64>,
) {
    let version = *countdown_version.read() + 1;

    spawn({
        to_owned![countdown, status, countdown_version];
        countdown_version.set(version);
        async move {
            status.set(AuthStatus::Sending);

            let res = send_code_request(email.read().clone()).await;

            match res {
                Ok(IsRateLimited::NotRateLimited) => {
                    status.set(AuthStatus::Sent);
                    countdown.set(90);

                    while *countdown.read() > 0 {
                        async_std::task::sleep(Duration::from_secs(1)).await;

                        if *countdown_version.read() != version {
                            break;
                        }

                        let remaining = countdown.read().saturating_sub(1);
                        countdown.set(remaining);
                    }

                    if *countdown_version.read() == version {
                        status.set(AuthStatus::Timeout);
                    }
                }
                Ok(IsRateLimited::RateLimited(cooldown)) => {
                    status.set(AuthStatus::Error(format!(
                        "Rate limited. Please wait below time"
                    )));
                    countdown.set(cooldown);

                    while *countdown.read() > 0 {
                        async_std::task::sleep(Duration::from_secs(1)).await;

                        if *countdown_version.read() != version {
                            break;
                        }

                        let remaining = countdown.read().saturating_sub(1);
                        countdown.set(remaining);
                    }
                }
                Err(err) => {
                    status.set(AuthStatus::Error(err));
                }
            }
        }
    });
}

enum IsRateLimited {
    RateLimited(u16),
    NotRateLimited,
}

#[derive(Serialize)]
struct SendCodeRequest {
    email: String,
}

async fn send_code_request(email: String) -> Result<IsRateLimited, String> {
    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:3002/register")
        .json(&serde_json::json!(&SendCodeRequest { email }))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    match res.status() {
        reqwest::StatusCode::OK => {
            return Ok(IsRateLimited::NotRateLimited);
        }
        reqwest::StatusCode::TOO_MANY_REQUESTS => {
            let data: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
            let cool_down = data.get("cooldown").and_then(|v| v.as_u64()).unwrap_or(600) as u16; // Default cooldown if not provided
            return Ok(IsRateLimited::RateLimited(cool_down)); // Assuming a cooldown of 600 seconds
        }
        _ => {
            return Err(format!("Unexpected status code: {}", res.status()));
        }
    }
}

fn on_resend_handler(
    email: Signal<String>,
    countdown: Signal<u16>,
    status: Signal<AuthStatus>,
    countdown_version: Signal<u64>,
) -> impl Fn(Event<MouseData>) {
    move |_| {
        trigger_send_code(email, countdown, status, countdown_version);
    }
}

#[derive(Serialize)]
struct VerifyCodeRequest {
    email: String,
    code: u32,
}

fn on_submit_handler(
    email: Signal<String>,
    code_input: Signal<String>,
    status: Signal<AuthStatus>,
    auth_token: Signal<String>,
) -> impl Fn(Event<MouseData>) {
    move |_| {
        let input_code = code_input.read().clone();
        let mut status = status.clone();
        let mut token = auth_token.clone();

        spawn(async move {
            let client = reqwest::Client::new();
            let res = client
                .post("http://localhost:3002/verify")
                .json(&serde_json::json!(&VerifyCodeRequest {
                    email: email.read().clone(),
                    code: input_code.parse::<u32>().unwrap()
                }))
                .send()
                .await
                .map_err(|e| format!("Request failed: {}", e))
                .unwrap();

            match res.status() {
                reqwest::StatusCode::OK => {
                    let body: serde_json::Value = res.json().await.unwrap();
                    if let Some(token_str) = body.get("token").and_then(|v| v.as_str()) {
                        token.set(token_str.to_string());
                        status.set(AuthStatus::Verified);
                    } else {
                        status.set(AuthStatus::Error("No token received".into()));
                    }
                }
                _ => {
                    status.set(AuthStatus::Error("Failed to verify code".into()));
                }
            }

            // match res {
            //     Ok(resp) => {
            //         if let Ok(json) = resp.json::<serde_json::Value>().await {
            //             if json.get("status") == Some(&serde_json::Value::String("ok".into())) {
            //                 if let Some(token_str) = json.get("token").and_then(|t| t.as_str()) {
            //                     token.set(token_str.to_string());
            //                     status.set(AuthStatus::Verified);
            //                 } else {
            //                     status.set(AuthStatus::Error("No token received".into()));
            //                 }
            //             } else {
            //                 status.set(AuthStatus::Error("Invalid code".into()));
            //             }
            //         } else {
            //             status.set(AuthStatus::Error("Invalid response".into()));
            //         }
            //     }
            //     Err(_) => status.set(AuthStatus::Error("Request failed".into())),
            // }
        });
    }
}
