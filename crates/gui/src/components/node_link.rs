use dioxus::prelude::*;

#[component]
pub fn NodeLinkForm() -> Element {
    let mut ip = use_signal(|| "192.168.0.1".to_string());
    let mut port = use_signal(|| "8080".to_string());
    let mut token = use_signal(String::new);
    let mut status = use_signal(|| None::<String>);

    let on_connect = move |_| {
        let target = format!("http://{}:{}", ip(), port());
        let auth_token = token();

        spawn(async move {
            match try_health_check(&target, &auth_token).await {
                Ok(_) => {
                    println!("Connection and health check passed.");
                    // TODO: Page navigation
                }
                Err(e) => {
                    status.set(Some(e));
                }
            }
        });
    };

    rsx! {
        div {
            style: "display: flex; flex-direction: column; align-items: center; background-color: #f2f2f2; min-height: 100vh;",

            div {
                style: "
                    width: 100%;
                    background-color: #1a1a1a;
                    padding: 20px 0;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
                    display: flex;
                    align-items: center;
                    justify-content: flex-start;
                    padding-left: 40px;
                ",
                h1 {
                    style: "color: white; font-size: 24px; font-weight: bold;",
                    "Mangonel"
                }
            }

            div {
                style: "
                    margin-top: 80px;
                    background-color: white;
                    padding: 32px;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    width: 320px;
                ",

                h2 {
                    style: "font-size: 20px; font-weight: bold; text-align: center; margin-bottom: 24px;",
                    "Access to the Equipment"
                }

                input {
                    style: "
                        width: 93%;
                        padding: 10px;
                        margin-bottom: 12px;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 16px;
                    ",
                    placeholder: "IP (ex: 192.168.0.1)",
                    value: "{ip()}",
                    oninput: move |e| ip.set(e.value())
                }

                input {
                    style: "
                        width: 93%;
                        padding: 10px;
                        margin-bottom: 12px;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 16px;
                    ",
                    placeholder: "Port (ex: 8080)",
                    value: "{port()}",
                    oninput: move |e| port.set(e.value())
                }

                input {
                    style: "
                        width: 93%;
                        padding: 10px;
                        margin-bottom: 20px;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 16px;
                    ",
                    placeholder: "Auth Token",
                    value: "{token()}",
                    oninput: move |e| token.set(e.value())
                }

                button {
                    onclick: on_connect,
                    style: "
                        width: 100%;
                        padding: 12px;
                        background-color: #007bff;
                        color: white;
                        font-weight: bold;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 16px;
                    ",
                    "Connect"
                }

                if let Some(message) = status() {
                    p {
                        style: "color: red; font-size: 14px; margin-top: 12px; padding-left: 4px;",
                        "{message}"
                    }
                }
            }
        }
    }
}

async fn try_health_check(target: &str, token: &str) -> Result<(), String> {
    let url = format!("{}/health", target);

    let res = reqwest::Client::new()
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;

    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("health check failed: {}", res.status()))
    }
}
