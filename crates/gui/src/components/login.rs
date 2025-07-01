use dioxus::prelude::*;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq)]
enum LoginState {
    Idle,
    Failure,
}

#[derive(Props, PartialEq, Clone)]
pub struct LoginFormProps {
    pub on_success: Callback<String>,
}

#[component]
pub fn LoginForm(props: LoginFormProps) -> Element {
    let mut id = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut login_state = use_signal(|| LoginState::Idle);

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
                    "Login"
                }

                if *login_state.read() == LoginState::Failure {
                    p {
                        style: "color: red; font-size: 14px; margin-bottom: 12px; text-align: center;",
                        "Wrong ID or password. Please try again."
                    }
                }

                input {
                    r#type: "text",
                    placeholder: "ID",
                    value: "{id.read()}",
                    oninput: move |e| id.set(e.value().to_string()),
                    style: "
                        width: 93%;
                        padding: 10px;
                        margin-bottom: 12px;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 16px;
                    ",
                }

                input {
                    r#type: "password",
                    placeholder: "Password",
                    value: "{password.read()}",
                    oninput: move |e| password.set(e.value().to_string()),
                    style: "
                        width: 93%;
                        padding: 10px;
                        margin-bottom: 20px;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 16px;
                    ",
                }

                button {
                    onclick: move |_| handle_login(id.clone(), password.clone(), props.clone(), &mut login_state),
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
                    ",
                    "Login"
                }
            }
        }
    }
}

#[derive(Serialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(serde::Deserialize)]
struct LoginSuccess {
    email: String,
}

fn handle_login(
    id: Signal<String>,
    password: Signal<String>,
    props: LoginFormProps,
    login_state: &mut Signal<LoginState>,
) {
    let id = id();
    let password = password();
    let mut login_state = login_state.to_owned();
    let on_success = props.on_success.clone();

    spawn(async move {
        let client = reqwest::Client::new();
        let res = client
            .post("http://localhost:3001/login")
            .json(&LoginRequest {
                email: id,
                password,
            })
            .send()
            .await;

        match res {
            Ok(response) => match response.status() {
                reqwest::StatusCode::OK => match response.json::<LoginSuccess>().await {
                    Ok(body) => {
                        login_state.set(LoginState::Idle);
                        on_success.call(body.email);
                    }
                    Err(_) => {
                        login_state.set(LoginState::Failure);
                    }
                },
                reqwest::StatusCode::TOO_MANY_REQUESTS => {
                    login_state.set(LoginState::Failure);
                    return;
                }
                reqwest::StatusCode::NOT_FOUND => {
                    login_state.set(LoginState::Failure);
                    return;
                }
                _ => {
                    login_state.set(LoginState::Failure);
                    return;
                }
            },
            Err(_) => {
                login_state.set(LoginState::Failure);
            }
        }
    });
}
