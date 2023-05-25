
use clubhouse_core::shapes::*;
use orion::errors::UnknownCryptoError;
use orion::kex::{EphemeralClientSession, EphemeralServerSession};


pub(crate) struct ServerKeyring {}

impl ServerKeyring {

    // pub fn encrypt_broadcast_emoji(
    //     keyring: &ClientServerKeyring, 
    //     plaintext: &str) -> EmojiCryptMessage {

    //     keyring.encrypt(
    //         EmojiCryptCodec::EmojiEncoded, 
    //         SenderType::Server, 
    //         plaintext.as_bytes()
    //     )
    // }

    // pub fn seal_with_emoji(
    //     keyring: &ServerKeyring,
    //     emoji_key: &str,
    // ) -> Result<EncryptedKeyring, UnknownCryptoError> {
    //     let shared_keyring = TopSecretSharedKeyring {
    //         a: keyring.broadcast.to_owned(),
    //         b: keyring.user.to_owned(),
    //         x: keyring.broadcast_secret.to_owned(),
    //         y: keyring.user_secret.to_owned(),
    //     };
    //     let message = serde_json::to_string(&shared_keyring).expect("serialize");
    //     let bytes = seal_with_key(emoji_key, &message.as_bytes()).expect("can seal shared keyring");
    //     Ok(EncryptedKeyring::encode(bytes.as_slice()))
    // }

    // pub fn open_with_emoji(
    //     shared_bytes: &EncryptedKeyring,
    //     emoji_key: &str
    // ) -> Result<ServerKeyring, UnknownCryptoError> {

    //     let bytes = open_with_key(emoji_key, &shared_bytes.b).expect("cannot decrypt keyring from shared bytes");

    //     let json = String::from_utf8(bytes).unwrap();

    //     let shared_keyring: TopSecretSharedKeyring =
    //         serde_json::from_str(&json).expect("valid json");

    //     Ok(ServerKeyring {
    //         broadcast: shared_keyring.a,
    //         user: shared_keyring.b,
    //         broadcast_secret: shared_keyring.x,
    //         user_secret: shared_keyring.y,
    //     })
    // }

    

    pub async fn from_sessions(
        session_server: EphemeralServerSession,
        session_client: EphemeralClientSession,
    ) -> Result<ClientServerKeyring, UnknownCryptoError> {
        let session_server_pub_key = session_server.public_key().clone();

        let session_client_pub_key = session_client.public_key().clone();

        let client_key_pair = session_client.establish_with_server(&session_server_pub_key)?;

        let server_identity = clubhouse_core::emoji::encode(&session_server_pub_key.to_bytes());
        let client_identity = clubhouse_core::emoji::encode(&session_client_pub_key.to_bytes());

        let server_secret = client_key_pair.receiving().unprotected_as_bytes();
        let client_secret = client_key_pair.transport().unprotected_as_bytes();

        let keyring = ClientServerKeyring {
            server: EmojiCryptContext {
                secret: server_secret.to_owned(), 
                sender: SenderType::Server, 
                sender_emoji_id: server_identity
            },
            client: EmojiCryptContext { 
                secret: client_secret.to_owned(), 
                sender: SenderType::Client, 
                sender_emoji_id: client_identity
            },
        };
        
        
        //         let client_rx_and_server_tx =
        //     clubhouse_core::emoji::encode(&);

        // let client_tx_and_server_rx =
        //     clubhouse_core::emoji::encode(&);

        // let bundle = ServerKeyring {
        //     broadcast: server_identity,
        //     user: client_identity,
        //     broadcast_secret: client_rx_and_server_tx,
        //     user_secret: client_tx_and_server_rx,
        // };

        Ok(keyring)
    }

    pub async fn new() -> Result<ClientServerKeyring, UnknownCryptoError> {
        let server_session = EphemeralServerSession::new()?;
        let client_session = EphemeralClientSession::new()?;
        ServerKeyring::from_sessions(server_session, client_session).await
    }
        

}
