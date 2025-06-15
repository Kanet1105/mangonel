use crate::components::two_factor::{TwoFactorForm, TwoFactorFormProps};
use dioxus::prelude::*;

#[component]
pub fn TwoFactorPage(props: TwoFactorFormProps) -> Element {
    rsx! {
        div {
            class: "h-screen flex items-center justify-center bg-gray-100",
            TwoFactorForm {
                on_success: props.on_success,
            }
        }
    }
}
