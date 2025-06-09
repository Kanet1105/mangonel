use dioxus::prelude::*;

#[component]
pub fn LoginForm() -> Element {
    rsx! {
        div {
            class: "bg-white shadow-md rounded px-8 pt-6 pb-8 w-full max-w-sm",
            h2 {
                class: "text-2xl font-bold mb-6 text-center",
                "Magonel"
            }
            input {
                class: "shadow border rounded w-full py-2 px-3 mb-4",
                r#type: "text",
                placeholder: "ID"
            }
            input {
                class: "shadow border rounded w-full py-2 px-3 mb-6",
                r#type: "password",
                placeholder: "Password"
            }
            button {
                class: "bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 w-full rounded",
                "Login"
            }
        }
    }
}
