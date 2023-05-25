use clubhouse_core::shapes::{ClientServerKeyring, SenderType, EmojiCryptCodec};
use clubhouse_core::encryption::EmojiCrypt;
use tide::prelude::*;
use tide::{http::mime, Redirect, Request, Response, Result};

use crate::dao;
use crate::util::password::PasswordUtil;
use crate::wiring::ServerWiring;

use clubhouse_core::emoji;

use domain::session::SessionUser;

use askama::Template; // bring trait in scope

#[derive(Template)] // this will generate the code...
#[template(path = "user/login.html.j2")] // using the template in this path, relative
struct LoginGetView {}

pub async fn get(req: Request<ServerWiring>) -> Result {
    let maybe_user: Option<&SessionUser> = req.ext();

    if maybe_user.is_some() {
        Ok(Redirect::new("/app").into())
    } else {
        let login_get_view = LoginGetView {};
        let message = login_get_view.render().unwrap();

        let secrets: &ClientServerKeyring = req.ext().unwrap();
        let encrypted_body = 
            EmojiCrypt::encrypt_emoji_server(secrets, message.as_bytes()).encrypted_message;

        let response = Response::builder(200)
            .content_type(mime::HTML)
            .body_string(encrypted_body)
            .build();
        Ok(response)
    }
}

#[derive(Debug, Deserialize)]
struct UserLoginDto {
    email: String, // emoji encrypted fields
    password: String,
}

pub async fn post(mut req: Request<ServerWiring>) -> Result {
    let form = {
        let encrypted_form: UserLoginDto = req.body_form().await?;

        let secrets: &ClientServerKeyring = req.ext().unwrap();

        let decrypted_email = EmojiCrypt::decrypt(secrets, &encrypted_form.email, EmojiCryptCodec::EmojiEncoded, SenderType::Client);

        let decrypted_password = EmojiCrypt::decrypt(secrets, &encrypted_form.password, EmojiCryptCodec::EmojiEncoded, SenderType::Client);

        let decrypted_email = String::from_utf8(decrypted_email).unwrap();
        let decrypted_password = String::from_utf8(decrypted_password).unwrap(); // todo: send a blake hash or something instead

        UserLoginDto {
            email: decrypted_email,
            password: decrypted_password,
        }
    };

    let plaintext_email = &form.email.as_bytes();
    let wiring: &ServerWiring = &req.state();
    let search = dao::user::UserDao::find_by_email(wiring, plaintext_email)
        .await
        .unwrap();

    if search.is_none() {
        let response = Response::builder(403).build();
        Ok(response)
    } else {
        let u = search.unwrap();

        let user_pwhash = emoji::decode(&u.password);
        let expected_email_hash = u.email_hash;

        let form_email_hash: &str = {
            // DeterministicEmojiEncrypt::new(
            //     &req.state().config.encryption_key_emoji,
            //     &req.state().config.encryption_salt_emoji,
            //     plaintext_email.to_owned(),
            // )
            todo!()
        };

        let email_is_valid = form_email_hash == expected_email_hash;

        let pass_is_valid =
            email_is_valid && { PasswordUtil::verify_hashed_bytes(&form.password, &user_pwhash) };

        if email_is_valid && pass_is_valid {
            let super_email = &wiring.config.super_user_email.as_bytes();

            let is_admin_user = plaintext_email == super_email;

            let session = req.session_mut();

            let user = SessionUser {
                email: String::from(&form.email),
                is_admin: is_admin_user,
            };

            let _res = session.insert("user", user.clone()).unwrap();

            // redirect to app now that we have set user
            Ok(Redirect::new("/app").into())
        } else {
            tide::log::info!("Failed login for user: {}", form.email);
            let response = Response::builder(403).build();
            Ok(response)
        }
    }
}
