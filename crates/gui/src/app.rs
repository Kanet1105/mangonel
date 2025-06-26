use crate::components::login::LoginForm;
use crate::components::node_link::NodeLinkForm;
use crate::components::two_factor::TwoFactorForm;
use dioxus::prelude::*;

#[component]
pub fn App() -> Element {
    let mut state = use_signal(|| AppState::Login);

    rsx! {
        match state.read().clone() {
            AppState::Login => rsx! {
                LoginForm {
                    on_success: move |email: String| state.set(AppState::TwoFactor(email.clone()))
                }
            },
            AppState::TwoFactor(email) => rsx! {
                TwoFactorForm {
                    email,
                    on_success: move || state.set(AppState::NodeLink)
                }
            },
            AppState::NodeLink => rsx! {
                NodeLinkForm { }
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AppState {
    Login,
    TwoFactor(String),
    NodeLink,
}
