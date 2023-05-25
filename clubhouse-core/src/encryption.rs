use orion::aead;

use orion::kex::SecretKey;

use crate::checksum::ChecksummingEncoder;
use crate::shapes::*;

pub struct EncryptionFunctions {}

impl EncryptionFunctions {
    pub fn open(secret: &[u8], message_bytes: &[u8]) -> Vec<u8> {
        let secret = SecretKey::from_slice(secret).unwrap();
        aead::open(&secret, &message_bytes).unwrap()
    }

    pub fn seal(secret: &[u8], message_bytes: &[u8]) -> Vec<u8> {
        let secret = SecretKey::from_slice(secret).unwrap();
        aead::seal(&secret, message_bytes).unwrap()
    }
}

pub struct EmojiCrypt {}
impl EmojiCrypt {
    pub fn from_encrypted_bytes(
        context: &EmojiCryptContext,
        encrypted_bytes: &[u8],
        original_bytes: &[u8],
        codec: EmojiCryptCodec,
    ) -> EmojiCryptMessage {
        let encrypted = ChecksummingEncoder::encode_with_checksum_and_source(
            codec,
            encrypted_bytes,
            original_bytes,
        );
        EmojiCryptMessage {
            sender: context.sender.clone(),
            sender_emoji_id: context.sender_emoji_id.clone(),
            encrypted_message: encrypted.message.encoded,
            message_codec: encrypted.message.codec,
            emoji_hash: encrypted.hash.encoded,
        }
    }

    pub fn encrypt_emoji_server(
        keyring: &ClientServerKeyring,
        message: &[u8],
    ) -> EmojiCryptMessage {
        EmojiCrypt::encrypt(
            keyring,
            EmojiCryptCodec::EmojiEncoded,
            SenderType::Server,
            message,
        )
    }

    pub fn encrypt_emoji_client(
        keyring: &ClientServerKeyring,
        message: &[u8],
    ) -> EmojiCryptMessage {
        EmojiCrypt::encrypt(
            keyring,
            EmojiCryptCodec::EmojiEncoded,
            SenderType::Client,
            message,
        )
    }

    pub fn encrypt_base64websafe_server(
        keyring: &ClientServerKeyring,
        message: &[u8],
    ) -> EmojiCryptMessage {
        EmojiCrypt::encrypt(
            keyring,
            EmojiCryptCodec::Base64Websafe,
            SenderType::Server,
            message,
        )
    }

    pub fn encrypt_base64websafe_client(
        keyring: &ClientServerKeyring,
        message: &[u8],
    ) -> EmojiCryptMessage {
        EmojiCrypt::encrypt(
            keyring,
            EmojiCryptCodec::Base64Websafe,
            SenderType::Client,
            message,
        )
    }

    pub fn encrypt(
        keyring: &ClientServerKeyring,
        codec: EmojiCryptCodec,
        sender: SenderType,
        message: &[u8],
    ) -> EmojiCryptMessage {
        let context = match sender {
            SenderType::Server => &keyring.server,
            SenderType::Client => &keyring.client,
        };
        let encrypted = EncryptionFunctions::seal(context.secret.as_slice(), message);
        EmojiCrypt::from_encrypted_bytes(context, encrypted.as_slice(), message, codec)
    }

    fn decrypt_with_codec_and_secret(
        secret: &[u8],
        codec: EmojiCryptCodec,
        encoded_bytes: &str,
    ) -> Vec<u8> {
        let decoded_bytes = match codec {
            EmojiCryptCodec::EmojiEncoded => crate::emoji::decode(encoded_bytes),
            EmojiCryptCodec::Base64 => crate::base64::decode(encoded_bytes),
            EmojiCryptCodec::Base64Websafe => crate::base64::decode_websafe(encoded_bytes),
        };

        EncryptionFunctions::open(secret, decoded_bytes.as_slice())
    }

    pub fn decrypt(
        keyring: &ClientServerKeyring,
        encoded_bytes: &str,
        codec: EmojiCryptCodec,
        sender: SenderType,
    ) -> Vec<u8> {
        let secret = match sender {
            SenderType::Server => keyring.server.secret.as_slice(),
            SenderType::Client => keyring.client.secret.as_slice(),
        };

        EmojiCrypt::decrypt_with_codec_and_secret(secret, codec, encoded_bytes)
    }

    pub fn decode_keyring(keyring: &TopSecretSharedKeyring) -> ClientServerKeyring {
        ClientServerKeyring {
            server: EmojiCryptContext {
                secret: crate::emoji::decode(&keyring.x),
                sender: SenderType::Server,
                sender_emoji_id: keyring.a.clone(),
            },
            client: EmojiCryptContext {
                secret: crate::emoji::decode(&keyring.y),
                sender: SenderType::Client,
                sender_emoji_id: keyring.b.clone(),
            },
        }
    }

    pub fn derive_session_secret(bytes: Vec<u8>) -> Vec<u8> {
        // reduce 128 bytes of the session id
        // into 32 bytes for our initial handshake key...

        // rely on this code to run this
        // "middle-out" key extraction

        let as_utf8 = String::from_utf8(bytes.clone()).unwrap();
        let chars = as_utf8.chars();

        let mut xs: Vec<char> = chars.take(32).step_by(2).collect();
        let mut ys: Vec<char> = as_utf8.chars().skip(33).step_by(2).collect();

        ys.append(&mut xs);

        let emoji_str: String = ys.into_iter().collect();

        let checksum = crate::emoji::EmojiEncodedBytes::emoji_checksum(&emoji_str);

        let signed = format!("{}{}", emoji_str, checksum);

        let e = crate::emoji::EmojiEncodedBytes { encoded: signed };

        e.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use orion::kex::SecretKey;

    use super::*;

    #[test]
    fn test_key_derive() {
        let emoji_str = "🚨🦕📲🦕💭🎵🏹🌊🌴🦆💝💲🍫🚶😙📞😻🤑🐸🍒📢🐷🎸💨🍊😣🤓🧡🚩🦝💡🌺🌈🍩😏💣✊🥂🧚🖕🐝🍎🥰😼🔒🤕🍪🍏👀🌴🐻🎯🐈🌾🤧🍭🦆🛒🛒💢💎🐣🔪👏🦝";
        let password = EmojiCrypt::derive_session_secret(emoji_str.as_bytes().to_owned());

        let key = SecretKey::from_slice(&password).unwrap();
        let secret = orion::aead::seal(&key, "secrets".as_bytes()).unwrap();

        let decrypted = String::from_utf8(orion::aead::open(&key, &secret).unwrap()).unwrap();

        assert_eq!(decrypted, "secrets");
    }
}
