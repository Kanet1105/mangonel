use dioxus::prelude::*;

#[component]
pub fn TwoFactorForm() -> Element {
    let mut code_input = use_signal(String::new);
    let mut countdown = use_signal(|| 180);

    {
        use_future(move || async move {
            while *countdown.read() > 0 {
                let current_count = *countdown.read();
                async_std::task::sleep(std::time::Duration::from_secs(1)).await;
                countdown.set(current_count - 1);
            }
        });
    }

    let on_submit = move |_| {
        if code_input.read().as_str() == "000000" {
            // TODO: Navigate to success page
        }
    };

    let resend = move |_| {
        // TODO: Backend call to send new code
        countdown.set(180);
    };

    rsx! {
        div {
            class: "flex flex-col items-center justify-center min-h-screen bg-gray-100 p-4",
            div {
                class: "bg-white shadow-md rounded px-8 pt-6 pb-8 w-full max-w-md",

                h2 {
                    class: "text-xl font-bold mb-4",
                    "2FA authentication"
                }

                p {
                    class: "text-gray-600 text-sm mb-2",
                    "Input the 6-digit code sent to your email."
                }

                input {
                    class: "shadow border rounded w-full py-2 px-3 mb-4 text-center text-lg tracking-widest",
                    maxlength: "6",
                    value: "{code_input.read()}",
                    oninput: move |e| code_input.set(e.value().to_string())
                }

                button {
                    class: "bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full mb-4",
                    onclick: on_submit,
                    "Confirm"
                }

                button {
                    class: "text-sm text-blue-500 hover:underline",
                    onclick: resend,
                    "Resend code"
                }

                if *countdown.read() == 0 {
                    p { class: "text-red-500 text-sm mt-4", "Timeout. Please try again." }
                } else {
                    p { class: "text-gray-500 text-sm mt-2", "Time left: {countdown} seconds" }
                }
            }
        }
    }
}
