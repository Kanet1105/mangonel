use crate::components::login::LoginForm;
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
                TwoFactorForm {  }
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AppState {
    Login,
    TwoFactor,
}
