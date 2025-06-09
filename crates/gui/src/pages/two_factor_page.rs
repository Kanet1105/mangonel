use crate::components::two_factor::TwoFactorForm;
use dioxus::prelude::*;

#[component]
pub fn TwoFactorPage() -> Element {
    rsx! {
        div {
            class: "h-screen flex items-center justify-center bg-gray-100",
            TwoFactorForm {}
        }
    }
}
