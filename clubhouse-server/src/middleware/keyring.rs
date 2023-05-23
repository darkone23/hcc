use clubhouse_core::encryption::EncryptedKeyring;

use crate::{wiring::ServerWiring, util::encryption::ServerKeyring};

#[derive(Default)]
pub struct SessionEncryptionMiddleware {

}

impl SessionEncryptionMiddleware {
    pub fn new() -> Self {
        Self {}
    }
}

#[tide::utils::async_trait]
impl tide::Middleware<ServerWiring> for SessionEncryptionMiddleware {
    async fn handle(
        &self,
        mut req: tide::Request<ServerWiring>,
        next: tide::Next<'_, ServerWiring>,
    ) -> tide::Result {
        let s = req.session();
        let secrets = match s.get::<EncryptedKeyring>("keyring") {
            Some(secrets) => {
                let emoji_key = &req.state().config.encryption_key_emoji;                
                ServerKeyring::open_with_emoji(&secrets, emoji_key).expect("decrypted keyring")
            },
            None => {
                let secrets = ServerKeyring::new().await.unwrap();
                let emoji_key = req.state().config.encryption_key_emoji.clone();

                let m = req.session_mut();
                let e: EncryptedKeyring = ServerKeyring::seal_with_emoji(&secrets, &emoji_key).expect("encrypted keyring");
                
                m.insert("keyring", e).expect("serializable");
                secrets
            }
        };
        req.set_ext(secrets);
        Ok(next.run(req).await)
    }
}
