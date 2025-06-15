use crate::components::node_link::NodeLinkForm;
use dioxus::prelude::*;

#[component]
pub fn NodeLinkPage() -> Element {
    rsx! {
        div {
            class: "h-screen flex items-center justify-center bg-gray-100",
            NodeLinkForm {}
        }
    }
}
