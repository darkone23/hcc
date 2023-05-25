use tide::{http::mime, Request, Response, Result};

use crate::wiring::ServerWiring;

use askama::Template;

use clubhouse_core::encryption::EmojiCrypt;
use clubhouse_core::shapes::ClientServerKeyring;

#[derive(Template)]
#[template(path = "brand/header.html.j2")]
struct BrandHeaderViewModel {}

#[derive(Template)]
#[template(path = "brand/sidebar.html.j2")]
struct BrandSidebarViewModel {}

#[derive(Template)]
#[template(path = "brand/splash.html.j2")]
struct BrandSplashViewModel {}

#[derive(Template)]
#[template(path = "brand/footer.html.j2")]
struct BrandFooterViewModel {}

pub async fn get_header(req: Request<ServerWiring>) -> Result {
    let view_context = BrandHeaderViewModel {};

    let secrets: &ClientServerKeyring = req.ext().unwrap();

    let encrypted_body =
        EmojiCrypt::encrypt_emoji_server(
            secrets,
            &view_context.render().unwrap().as_bytes()
        ).encrypted_message;

    let response = Response::builder(200)
        .content_type(mime::HTML)
        .body_string(encrypted_body)
        .build();

    Ok(response)
}

pub async fn get_sidebar(req: Request<ServerWiring>) -> Result {
    let view_context = BrandSidebarViewModel {};

    let secrets: &ClientServerKeyring = req.ext().unwrap();

    let encrypted_body =
        EmojiCrypt::encrypt_emoji_server(
            secrets,
            &view_context.render().unwrap().as_bytes()
        ).encrypted_message;

    let response = Response::builder(200)
        .content_type(mime::HTML)
        .body_string(encrypted_body)
        .build();

    Ok(response)
}

pub async fn get_splash(req: Request<ServerWiring>) -> Result {
    let view_context = BrandSplashViewModel {};

    let secrets: &ClientServerKeyring = req.ext().unwrap();

    let encrypted_body =
        EmojiCrypt::encrypt_emoji_server(
            secrets,
            &view_context.render().unwrap().as_bytes()
        ).encrypted_message;

    let response = Response::builder(200)
        .content_type(mime::HTML)
        .body_string(encrypted_body)
        .build();

    Ok(response)
}

pub async fn get_footer(req: Request<ServerWiring>) -> Result {
    let view_context = BrandFooterViewModel {};

    let secrets: &ClientServerKeyring = req.ext().unwrap();

    let encrypted_body =
        EmojiCrypt::encrypt_emoji_server(
            secrets,
            &view_context.render().unwrap().as_bytes()
        ).encrypted_message;

    let response = Response::builder(200)
        .content_type(mime::HTML)
        .body_string(encrypted_body)
        .build();

    Ok(response)
}
