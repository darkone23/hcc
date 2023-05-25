use tide::{http::mime, Request, Result};

use crate::wiring::ServerWiring;
use clubhouse_core::shapes::{ClientServerKeyring, EmojiCryptMessage};
use clubhouse_core::encryption::EmojiCrypt;

pub async fn get(req: Request<ServerWiring>) -> Result {
    let secrets = req.ext::<ClientServerKeyring>().unwrap();

    let body = String::from("<div>YOU ARE AUTHORIZED!</div>");
    let message: EmojiCryptMessage = EmojiCrypt::encrypt_emoji_server(secrets, body.as_bytes());
    let encrypted_body = message.encrypted_message;

    Ok(tide::Response::builder(200)
        .content_type(mime::PLAIN)
        .body_string(encrypted_body)
        .build())
}
