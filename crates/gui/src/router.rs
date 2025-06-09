use dioxus::prelude::*;

use crate::pages::login_page::LoginPage;

#[derive(Routable, Clone)]
pub enum Route {
    #[route("/")]
    LoginPage,
}
