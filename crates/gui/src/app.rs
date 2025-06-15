use crate::components::login::LoginForm;
use crate::components::node_link::NodeLinkForm;
use crate::components::two_factor::TwoFactorForm;
use dioxus::prelude::*;

#[component]
pub fn App() -> Element {
    let mut state = use_signal(|| AppState::Login);

    rsx! {
        match *state.read() {
            AppState::Login => rsx! {
                LoginForm {
                    on_success: move || state.set(AppState::TwoFactor)
                }
            },
            AppState::TwoFactor => rsx! {
                TwoFactorForm {
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
    TwoFactor,
    NodeLink,
}
