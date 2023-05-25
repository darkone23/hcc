use tide::{http::mime, Request, Response, Result, Redirect};

use crate::wiring::ServerWiring;
use domain::session::SessionUser;

use clubhouse_core::encryption::EmojiCrypt;
use clubhouse_core::shapes::ClientServerKeyring;

use askama::Template; // bring trait in scope

#[derive(Template)] // this will generate the code...
#[template(path = "app.html.j2")] // using the template in this path, relative
struct AppView {
    user: SessionUser,
}

pub async fn get(req: Request<ServerWiring>) -> Result {
    let maybe_user: Option<&SessionUser> = req.ext();

    if maybe_user.is_some() {
        let user = maybe_user.unwrap().to_owned();

        let secrets: &ClientServerKeyring = req.ext().unwrap();
        
        let app_view = AppView { user };

        let encrypted_body =
            EmojiCrypt::encrypt_emoji_server(
                secrets,
                &app_view.render().unwrap().as_bytes()
            ).encrypted_message;

        let response = Response::builder(200)
            .content_type(mime::PLAIN)
            .body_string(encrypted_body)
            .build();

        Ok(response)
    } else {
        Ok(Redirect::new("/login").into())
    }
}