use dioxus::prelude::*;

#[derive(Debug, Clone, PartialEq)]
enum LoginState {
    Idle,
    Failure,
}

#[derive(Props, PartialEq, Clone)]
pub struct LoginFormProps {
    pub on_success: Callback<()>,
}

#[component]
pub fn LoginForm(props: LoginFormProps) -> Element {
    let mut id = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut login_state = use_signal(|| LoginState::Idle);

    // let navigator = dioxus_router::prelude::use_navigator();

    let handle_login = {
        // let mut login_state = login_state.clone();
        // let id = id.clone();
        // let password = password.clone();
        {
            let props = props.clone();
            move |_| {
                let user = id.read();
                let pass = password.read();

                if user.as_str() == "admin" && pass.as_str() == "1234" {
                    // navigator.push(crate::router::Route::TwoFactorPage {});
                    props.on_success.call(());
                } else {
                    login_state.set(LoginState::Failure);
                }
            }
        }
    };

    rsx! {
        div {
            class: "bg-white shadow-md rounded px-8 pt-6 pb-8 w-full max-w-sm",

            h2 {
                class: "text-2xl font-bold mb-6 text-center",
                "Mangonel"
            }

            if matches!(*login_state.read(), LoginState::Failure) {
                p {
                    class: "text-red-500 text-sm mb-4",
                    "Wrong ID or password. Please try again."
                }
            }

            input {
                class: "shadow border rounded w-full py-2 px-3 mb-4",
                placeholder: "ID",
                value: id.read().to_string(),
                oninput: move |e| id.set(e.value().to_string()),
            }

            input {
                class: "shadow border rounded w-full py-2 px-3 mb-6",
                r#type: "password",
                placeholder: "Password",
                value: password.read().to_string(),
                oninput: move |e| password.set(e.value().to_string()),
            }

            button {
                class: "bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 w-full rounded",
                onclick: handle_login,
                "Login"
            }
        }
    }
}
