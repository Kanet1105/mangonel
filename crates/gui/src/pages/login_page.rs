use crate::components::login::LoginForm;
use dioxus::prelude::*;

#[component]
pub fn LoginPage() -> Element {
    rsx! {
        div {
            class: "h-screen flex items-center justify-center bg-gray-100",
            LoginForm {}
        }
    }
}
