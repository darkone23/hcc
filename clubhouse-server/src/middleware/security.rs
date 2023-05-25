use clubhouse_core::{encryption::EmojiCrypt, shapes::{ClientServerKeyring, EmojiCryptCodec, SenderType}};
use tide::http::Method;

use crate::wiring::ServerWiring;

#[derive(Default)]
pub struct AntiRequestForgeryMiddleware {}

impl AntiRequestForgeryMiddleware {
    pub fn new() -> Self {
        Self {}
    }

    fn unauthorized() -> tide::Result<tide::Response> {
        Ok(tide::Response::builder(403).build())
    }
}

#[tide::utils::async_trait]
impl tide::Middleware<ServerWiring> for AntiRequestForgeryMiddleware {
    async fn handle(
        &self,
        req: tide::Request<ServerWiring>,
        next: tide::Next<'_, ServerWiring>,
    ) -> tide::Result {
        let should_protect_route = match req.method() {
            Method::Get => false,
            Method::Post | Method::Put | Method::Patch | Method::Delete => true,
            _ => false,
        };

        if should_protect_route {
            let maybe_csrf_header = req.header("x-anti-forgery-token");

            if maybe_csrf_header.is_some() {
                let maybe_token_text = maybe_csrf_header.unwrap().into_iter().next();
                if maybe_token_text.is_some() {
                    let jwt_util = &req.state().services.jwt_util;
                    let session = req.session();
                    let secrets: &ClientServerKeyring = req.ext().unwrap();

                    let encoded_bytes = maybe_token_text.unwrap().as_str();

                    let decrypted_bytes =
                         EmojiCrypt::decrypt(secrets, encoded_bytes, EmojiCryptCodec::Base64Websafe, SenderType::Client);
                    let jwt_claims =
                        &String::from_utf8(decrypted_bytes).unwrap();

                    let verification = jwt_util.verify_csrf_token(
                        jwt_claims,
                        session.id(), 
                    );
                    if verification.is_ok() {
                        Ok(next.run(req).await)
                    } else {
                        tide::log::info!("Rejecting bad anti forgery verification");
                        AntiRequestForgeryMiddleware::unauthorized()
                    }
                } else {
                    tide::log::info!("No anti forgery token present");
                    AntiRequestForgeryMiddleware::unauthorized()
                }
            } else {
                tide::log::info!("No anti forgery token present");
                AntiRequestForgeryMiddleware::unauthorized()
            }
        } else {
            Ok(next.run(req).await)
        }
    }
}