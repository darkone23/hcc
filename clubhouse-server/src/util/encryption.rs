
use orion::errors::UnknownCryptoError;
use orion::kex::{EphemeralClientSession, EphemeralServerSession};


use clubhouse_core::encryption::{seal_with_key_emoji, open_with_key, seal_with_key, EncryptedKeyring};
use clubhouse_core::encryption::ServerEncryptedEmojiMessage;
use clubhouse_core::encryption::TopSecretSharedKeyring;

#[derive(Clone)]
pub struct ServerKeyring {
    // how do we get some sort of forward secrecy? or post-compromise security?
    // rotate your keys, orion wants these to be single use keys...

    // good security practice dictates you throw these away frequently
    // we store them on our session and rely on browser http only cookie security
    pub broadcast: String,
    pub user: String,

    pub broadcast_secret: String,
    pub user_secret: String,
}


impl ServerKeyring {

    pub async fn encrypt_broadcast_emoji(
        &self,
        plaintext: &str,
    ) -> Result<ServerEncryptedEmojiMessage, UnknownCryptoError> {
        let message = seal_with_key_emoji(&self.broadcast_secret, plaintext.as_bytes())?;

        Ok(ServerEncryptedEmojiMessage {
            sender: self.broadcast.to_owned(),
            message,
        })
    }

    pub fn seal_with_emoji(
        keyring: &ServerKeyring,
        emoji_key: &str,
    ) -> Result<EncryptedKeyring, UnknownCryptoError> {
        let shared_keyring = TopSecretSharedKeyring {
            a: keyring.broadcast.to_owned(),
            b: keyring.user.to_owned(),
            x: keyring.broadcast_secret.to_owned(),
            y: keyring.user_secret.to_owned(),
        };
        let message = serde_json::to_string(&shared_keyring).expect("serialize");
        let bytes = seal_with_key(emoji_key, &message.as_bytes()).expect("can seal shared keyring");
        Ok(EncryptedKeyring::encode(bytes.as_slice()))
    }

    pub fn open_with_emoji(
        shared_bytes: &EncryptedKeyring,
        emoji_key: &str
    ) -> Result<ServerKeyring, UnknownCryptoError> {

        let bytes = open_with_key(emoji_key, &shared_bytes.b).expect("cannot decrypt keyring from shared bytes");

        let json = String::from_utf8(bytes).unwrap();

        let shared_keyring: TopSecretSharedKeyring =
            serde_json::from_str(&json).expect("valid json");

        Ok(ServerKeyring {
            broadcast: shared_keyring.a,
            user: shared_keyring.b,
            broadcast_secret: shared_keyring.x,
            user_secret: shared_keyring.y,
        })
    }

    

    pub async fn from(
        session_server: EphemeralServerSession,
        session_client: EphemeralClientSession,
    ) -> Result<ServerKeyring, UnknownCryptoError> {
        let session_server_pub_key = session_server.public_key().clone();

        let session_client_pub_key = session_client.public_key().clone();

        let client_key_pair = session_client.establish_with_server(&session_server_pub_key)?;

        let server_identity = clubhouse_core::emoji::encode(&session_server_pub_key.to_bytes());
        let client_identity = clubhouse_core::emoji::encode(&session_client_pub_key.to_bytes());

        let client_rx_and_server_tx =
            clubhouse_core::emoji::encode(&client_key_pair.receiving().unprotected_as_bytes());

        let client_tx_and_server_rx =
            clubhouse_core::emoji::encode(&client_key_pair.transport().unprotected_as_bytes());

        let bundle = ServerKeyring {
            broadcast: server_identity,
            user: client_identity,
            broadcast_secret: client_rx_and_server_tx,
            user_secret: client_tx_and_server_rx,
        };

        Ok(bundle)
    }

    pub async fn new() -> Result<ServerKeyring, UnknownCryptoError> {
        let server_session = EphemeralServerSession::new()?;
        let client_session = EphemeralClientSession::new()?;
        ServerKeyring::from(server_session, client_session).await
    }
        

    
}

