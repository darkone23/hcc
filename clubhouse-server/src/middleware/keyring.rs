use clubhouse_core::{shapes::{TopSecretSharedKeyring, ClientServerKeyring, EncryptedKeyring}, emoji};

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

    /*

        this middleware puts the client server keyring into the session if it is not already there

            the keyring gets shoved into the persistent session so it can be pulled easily
            because of that we make sure the keyring is encrypted using the server encryption key

    */
    async fn handle(
        &self,
        mut req: tide::Request<ServerWiring>,
        next: tide::Next<'_, ServerWiring>,
    ) -> tide::Result {
        let s = req.session();

        let secrets: ClientServerKeyring = {
            let emoji_key = &req.state().config.encryption_key_emoji;                
            let emoji_secret = clubhouse_core::emoji::decode(emoji_key);
            
            match s.get::<EncryptedKeyring>("keyring") {
                Some(secrets) => {
                    let encoded_secrets: &str = &secrets.b;
                    let decoded = clubhouse_core::encryption::EncryptionFunctions::open(
                        emoji_secret.as_slice(), 
                        emoji::decode(encoded_secrets).as_slice()
                    );

                    let json = String::from_utf8(decoded).unwrap();

                    let shared_keyring: TopSecretSharedKeyring =
                        serde_json::from_str(&json).expect("valid json");

                    clubhouse_core::encryption::EmojiCrypt::decode_keyring(&shared_keyring)
                },
                None => {
                    let secrets: ClientServerKeyring = ServerKeyring::new().await.unwrap();

                    let m = req.session_mut();

                    let shared_keyring = TopSecretSharedKeyring {
                        a: secrets.server.sender_emoji_id.clone(),
                        b: secrets.client.sender_emoji_id.clone(),
                        x: clubhouse_core::emoji::encode(secrets.server.secret.as_slice()),
                        y: clubhouse_core::emoji::encode(secrets.client.secret.as_slice()),
                    };

                    let message = serde_json::to_string(&shared_keyring).expect("serialize");

                    let encrypted_bytes = clubhouse_core::encryption::EncryptionFunctions::seal(&emoji_secret, message.as_bytes());

                    let e = EncryptedKeyring {
                        b: clubhouse_core::emoji::encode(encrypted_bytes.as_slice())
                    };

                    m.insert("keyring", e).expect("serializable");
                    secrets
                }
            }
        };

        req.set_ext(secrets);
        Ok(next.run(req).await)
    }
}
