use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub enum EmojiCryptCodec {
    EmojiEncoded,
    Base64,
    Base64Websafe,
}

#[derive(Clone, Debug)]
pub struct EncodedBytes {
    pub encoded: String,
    pub codec: EmojiCryptCodec,
}

#[derive(Clone, Debug)]
pub struct EncodedMessageWithChecksum {
    pub message: EncodedBytes,
    pub hash: EncodedBytes,
}

#[derive(Clone, Debug)]
pub enum SenderType {
    Server,
    Client,
}

#[derive(Clone, Debug)]
pub struct EmojiCryptMessage {
    pub encrypted_message: String,
    pub message_codec: EmojiCryptCodec,
    pub emoji_hash: String,
    pub sender: SenderType,
    pub sender_emoji_id: String,
}

#[derive(Clone, Debug)]
pub struct EmojiCryptContext {
    pub secret: Vec<u8>,
    pub sender: SenderType,
    pub sender_emoji_id: String,
}

impl EmojiCryptContext {
    pub fn empty(sender: SenderType) -> Self {
        Self {
            secret: vec![],
            sender,
            sender_emoji_id: String::from(""),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedKeyring {
    pub b: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TopSecretSharedKeyring {
    pub a: String, // server id pubkey bytes, emoji encoded
    pub b: String, // client id pubkey bytes, emoji encoded
    pub x: String, // server secret, emoji encoded
    pub y: String, // client secret, emoji encoded
}

#[derive(Clone, Debug)]
pub struct ClientServerKeyring {
    pub server: EmojiCryptContext,
    pub client: EmojiCryptContext,
}

impl ClientServerKeyring {
    pub fn empty() -> Self {
        Self {
            server: EmojiCryptContext::empty(SenderType::Server),
            client: EmojiCryptContext::empty(SenderType::Client),
        }
    }
}
