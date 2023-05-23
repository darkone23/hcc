use crate::wiring::ServerWiring;
use clubhouse_core::encryption::{SharedKeyring, UserEncryptedBase64Message};
use domain::session::SessionUser;

#[derive(Default)]
pub struct UserAuthorizationMiddleware {}

impl UserAuthorizationMiddleware {
    pub fn new() -> Self {
        Self {}
    }

    fn unauthorized() -> tide::Result<tide::Response> {
        Ok(tide::Response::builder(403).build())
    }
}

#[tide::utils::async_trait]
impl tide::Middleware<ServerWiring> for UserAuthorizationMiddleware {

    // implements JWT authorization

    // this middleware verifies the request has been signed by the user
    // expects the user to have identified the auth token we sent them

    async fn handle(
        &self,
        req: tide::Request<ServerWiring>,
        next: tide::Next<'_, ServerWiring>,
    ) -> tide::Result {

        let maybe_user: Option<&SessionUser> = req.ext(); // comes from async-session
        if let Some(user) = maybe_user {

            let maybe_auth_token = req.header("x-auth-token");
            if let Some(header) = maybe_auth_token {

                let maybe_header_value = header.into_iter().next().map(|x| x.as_str());
                if let Some(message) = maybe_header_value {

                    let jwt_util = &req.state().services.jwt_util;
                    let secrets: &SharedKeyring = req.ext().unwrap();

                    let message = UserEncryptedBase64Message { message: message.to_owned() };

                    let decrypted = message.decrypt(&secrets.user_secret).unwrap();

                    let verification = jwt_util.verify_auth_token(&decrypted, &user.email);

                    if verification.is_ok() {
                        Ok(next.run(req).await)
                    } else {
                        tide::log::info!("Invalid authorization token");
                        UserAuthorizationMiddleware::unauthorized()
                    }
                } else {
                    tide::log::info!("Missing authorization token value");
                    UserAuthorizationMiddleware::unauthorized()
                }
            } else {
                tide::log::info!("Missing authorization token");
                UserAuthorizationMiddleware::unauthorized()
            }            
        } else {
            tide::log::info!("Missing required session user");
            UserAuthorizationMiddleware::unauthorized()
        }

    }
}