use crate::wiring::ServerWiring;
use domain::session::SessionUser;

#[derive(Default)]
pub struct UserExtensionMiddleware {}

impl UserExtensionMiddleware {
    pub fn new() -> Self {
        Self {}
    }
}

#[tide::utils::async_trait]
impl tide::Middleware<ServerWiring> for UserExtensionMiddleware {
    async fn handle(
        &self,
        mut req: tide::Request<ServerWiring>,
        next: tide::Next<'_, ServerWiring>,
    ) -> tide::Result {

        // if we find a registered user: 
        // - put the user in the request context
        // - sign an auth token for them 
        //   - give it back to the client in our response header

        let maybe_user: Option<SessionUser> = req.session().get("user");

        let auth_token = // base64_websafe jwt claims
            if maybe_user.is_some() {
                let user = maybe_user.unwrap();
                let maybe_user = req.state().services.jwt_util.sign_auth_token(&user.email);
                req.set_ext(user);
                match maybe_user {
                    Ok(token) => Some(token),
                    _ => None
                }
            } else {
                None
            };

        if auth_token.is_some() {
            let secrets: &clubhouse_core::shapes::ClientServerKeyring = req.ext().unwrap();

            let jwt_claims = auth_token.unwrap();

            let encrypted = clubhouse_core::encryption::EmojiCrypt::encrypt_base64websafe_server(
                secrets, 
                jwt_claims.as_bytes()
            ).encrypted_message;

            let mut res = next.run(req).await;
            res.insert_header("x-auth-token", encrypted);

            Ok(res)


            
        } else {
            Ok(next.run(req).await)
        }
    }
}