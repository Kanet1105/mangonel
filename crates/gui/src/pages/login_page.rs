use crate::components::login::{LoginForm, LoginFormProps};
use dioxus::prelude::*;

#[component]
pub fn LoginPage(props: LoginFormProps) -> Element {
    rsx! {
        div {
            class: "h-screen flex items-center justify-center bg-gray-100",
            LoginForm {
                on_success: props.on_success
            }
        }
    }
}
