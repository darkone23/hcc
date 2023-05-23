use serde::{Deserialize, Serialize};

use orion::aead;
use orion::aead::streaming::Nonce;
use orion::errors::UnknownCryptoError;
use orion::hazardous::aead::xchacha20poly1305;
use orion::hazardous::mac::poly1305::POLY1305_OUTSIZE;
use orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE;
use orion::kex::SecretKey;

use orion::hazardous::hash::blake2::blake2b;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerEncryptedEmojiMessage {
    pub sender: String,
    pub message: String,
}

impl ServerEncryptedEmojiMessage {
    pub fn decrypt(&self, broadcast_secret: &str) -> Result<String, UnknownCryptoError> {
        let secret_bytes = crate::emoji::decode(broadcast_secret);
        let secret = SecretKey::from_slice(&secret_bytes)?;

        let message_bytes = crate::emoji::decode(&self.message);

        let bytes = aead::open(&secret, &message_bytes)?;
        let s = String::from_utf8(bytes).expect("invalid utf8");
        Ok(s)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserEncryptedEmojiMessage {
    pub sender: String,
    pub message: String,
}

impl UserEncryptedEmojiMessage {
    pub fn decrypt(&self, user_secret: &str) -> Result<String, UnknownCryptoError> {
        let secret_bytes = crate::emoji::decode(user_secret);
        let secret = SecretKey::from_slice(&secret_bytes)?;
        let message_bytes = crate::emoji::decode(&self.message);
        let bytes = aead::open(&secret, &message_bytes)?;
        let s = String::from_utf8(bytes).expect("invalid utf8");
        Ok(s)
    }
}

pub struct ServerEncryptedBase64Message {
    pub message: String,
}

impl ServerEncryptedBase64Message {
    pub fn decrypt(&self, broadcast_secret: &str) -> Result<String, UnknownCryptoError> {
        let secret_bytes = crate::emoji::decode(broadcast_secret);
        let secret = SecretKey::from_slice(&secret_bytes)?;

        let message_bytes = base64::decode_config(&self.message, base64::URL_SAFE_NO_PAD).unwrap();
        let bytes = aead::open(&secret, &message_bytes)?;
        let s = String::from_utf8(bytes).expect("invalid utf8");
        Ok(s)
    }
}

pub struct UserEncryptedBase64Message {
    pub message: String,
}

impl UserEncryptedBase64Message {
    pub fn decrypt(&self, user_secret: &str) -> Result<String, UnknownCryptoError> {
        let secret_bytes = crate::emoji::decode(user_secret);
        let secret = SecretKey::from_slice(&secret_bytes)?;

        let message_bytes = base64::decode_config(&self.message, base64::URL_SAFE_NO_PAD).unwrap();
        let bytes = aead::open(&secret, &message_bytes)?;
        let s = String::from_utf8(bytes).expect("invalid utf8");
        Ok(s)
    }
}

pub enum SmallBlakeHasher {
    /// Blake2b with `24` as `size`.
    Blake2b24,
    /// Blake2b with `32` as `size`.
    Blake2b32,
}

impl SmallBlakeHasher {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a digest selected by the given Blake2b variant.
    pub fn digest(&self, data: &[u8]) -> Result<blake2b::Digest, UnknownCryptoError> {
        let size: usize = match *self {
            SmallBlakeHasher::Blake2b24 => 24,
            SmallBlakeHasher::Blake2b32 => 32,
        };

        let mut state = blake2b::Blake2b::new(size)?;
        state.update(data)?;
        state.finalize()
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a `Blake2b` state selected by the given Blake2b variant.
    pub fn init(&self) -> Result<blake2b::Blake2b, UnknownCryptoError> {
        match *self {
            SmallBlakeHasher::Blake2b24 => blake2b::Blake2b::new(24),
            SmallBlakeHasher::Blake2b32 => blake2b::Blake2b::new(32),
        }
    }
}

pub struct DeterministicEmojiEncrypt {
    pub encrypted: String,
}

impl DeterministicEmojiEncrypt {
    fn get_hash_nonce(
        __salt_bytes: &Vec<u8>,
        plaintext_bytes: &[u8],
    ) -> Result<Vec<u8>, UnknownCryptoError> {
        // todo: we should salt the plaintext bytes so this hash is a little harder to get to
        let hashcode = SmallBlakeHasher::Blake2b24.digest(plaintext_bytes)?;
        let nonce_bytes = &hashcode.as_ref();
        Ok(nonce_bytes.to_vec())
    }

    pub fn new(
        emoji_encoded_secret: &str,
        emoji_encoded_salt: &str,
        plaintext_bytes: &[u8],
    ) -> Result<DeterministicEmojiEncrypt, UnknownCryptoError> {
        let secret_bytes = crate::emoji::decode(emoji_encoded_secret);
        let salt_bytes = crate::emoji::decode(emoji_encoded_salt);
        let nonce_bytes = Self::get_hash_nonce(&salt_bytes, plaintext_bytes)?;

        let encrypted = seal_hazardous(&secret_bytes, &nonce_bytes, plaintext_bytes)?;

        let encoded = crate::emoji::encode(&encrypted);

        let i = DeterministicEmojiEncrypt { encrypted: encoded };

        Ok(i)
    }
}

pub fn open_with_key(
    emoji_encoded_secret: &str,
    emoji_cipher_message: &str,
) -> Result<Vec<u8>, UnknownCryptoError> {
    let cipher_bytes = crate::emoji::decode(emoji_cipher_message);
    let secret_slice = crate::emoji::decode(emoji_encoded_secret);

    let secret: SecretKey = SecretKey::from_slice(&secret_slice)?;
    let bytes = aead::open(&secret, &cipher_bytes)?;

    Ok(bytes)
}

pub fn seal_with_key(
    emoji_encoded_secret: &str,
    plaintext_bytes: &[u8],
) -> Result<Vec<u8>, UnknownCryptoError> {
    let secret_bytes = crate::emoji::decode(emoji_encoded_secret);
    let secret = SecretKey::from_slice(&secret_bytes)?;
    let bytes = aead::seal(&secret, plaintext_bytes)?;
    Ok(bytes)
}

pub fn seal_with_key_emoji(
    emoji_encoded_secret: &str,
    plaintext_bytes: &[u8],
) -> Result<String, UnknownCryptoError> {
    let bytes = seal_with_key(emoji_encoded_secret, plaintext_bytes)?;
    let message = crate::emoji::encode(&bytes);
    Ok(message)
}

pub fn seal_hazardous(
    secret_bytes: &Vec<u8>,
    nonce_bytes: &Vec<u8>,
    plaintext_bytes: &[u8],
) -> Result<Vec<u8>, UnknownCryptoError> {
    /*

        do not re-use the same nonce on different plaintext bytes

        a very clever attacker can intercept these masked messages and reverse engineer their way to the plaintext
        the basic security relies on the fact the nonce will a number which is only used once

        our actual guarantee is that for each value, we have a unique nonce: the same nonce yield the same bytes encrypting the same bytes
        - WARNING: if the same nonce is used to decrypt two values then the values can be used to decrypt one another!

    */

    let _key = SecretKey::from_slice(&secret_bytes)?;

    // adapted from aead::seal()

    let out_len = match plaintext_bytes
        .len()
        .checked_add(XCHACHA_NONCESIZE + POLY1305_OUTSIZE)
    {
        Some(min_out_len) => min_out_len,
        None => return Err(UnknownCryptoError),
    };

    let nonce = Nonce::from_slice(&nonce_bytes).unwrap();

    let mut dst_out = vec![0u8; out_len];

    dst_out[..XCHACHA_NONCESIZE].copy_from_slice(nonce.as_ref());

    xchacha20poly1305::seal(
        &orion::hazardous::aead::chacha20poly1305::SecretKey::from_slice(
            _key.unprotected_as_bytes(),
        )?,
        &nonce,
        plaintext_bytes,
        None,
        &mut dst_out[XCHACHA_NONCESIZE..],
    )?;

    Ok(dst_out)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedKeyring {
    pub b: String,
}

#[allow(dead_code)]
impl EncryptedKeyring {
    pub fn encode(bytes: &[u8]) -> Self {
        EncryptedKeyring {
            b: crate::emoji::encode(bytes),
        }
    }

    pub fn seal_with_emoji(
        // keyring, &config.encryption_key_emoji
        message: &str,
        emoji_key: &str,
    ) -> Result<EncryptedKeyring, UnknownCryptoError> {
        let bytes = seal_with_key(emoji_key, &message.as_bytes())?;
        Ok(EncryptedKeyring::encode(bytes.as_slice()))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TopSecretSharedKeyring {
    pub a: String,
    pub b: String,
    pub x: String,
    pub y: String,
}

#[derive(Clone)]
pub struct SharedKeyring {
    // how do we get some sort of forward secrecy? or post-compromise security?
    // rotate your keys, orion wants these to be single use keys...

    // good security practice dictates you throw these away frequently
    // we store them on our session and rely on browser http only cookie security
    pub broadcast: String,
    pub user: String,

    pub broadcast_secret: String,
    pub user_secret: String,
}

impl SharedKeyring {
    pub fn decrypt_emoji_from_slice(secret: &[u8], encrypted: &str) -> String {
        let message_bytes = crate::emoji::decode(encrypted);
        SharedKeyring::decrypt_bytes_from_slice(secret, message_bytes.as_slice())
    }

    pub fn decrypt_bytes_to_string(secret: &str, message_bytes: &[u8]) -> String {
        SharedKeyring::decrypt_bytes_from_slice(secret.as_bytes(), message_bytes)
    }

    pub fn decrypt_bytes_from_slice(slice: &[u8], message_bytes: &[u8]) -> String {
        let secret = SecretKey::from_slice(slice).unwrap();
        let bytes = aead::open(&secret, &message_bytes).unwrap();
        String::from_utf8(bytes).expect("invalid utf8")
    }

    pub fn encrypt_emoji_from_slice(secret: &[u8], plaintext: &str) -> String {
        let message_bytes = plaintext.as_bytes();
        let encrypted_bytes = SharedKeyring::encrypt_bytes_from_slice(secret, message_bytes);
        crate::emoji::encode(&encrypted_bytes)
    }

    pub fn encrypt_bytes(secret: &str, message_bytes: &[u8]) -> Vec<u8> {
        SharedKeyring::encrypt_bytes_from_slice(secret.as_bytes(), message_bytes)
    }

    pub fn encrypt_bytes_from_slice(slice: &[u8], message_bytes: &[u8]) -> Vec<u8> {
        let secret = SecretKey::from_slice(slice).unwrap();
        aead::seal(&secret, message_bytes).expect("invalid bytes")
    }

    pub async fn encrypt_broadcast_base64(
        &self,
        plaintext: &str,
    ) -> Result<ServerEncryptedBase64Message, UnknownCryptoError> {
        let secret_bytes = crate::emoji::decode(&self.broadcast_secret);
        let secret = SecretKey::from_slice(&secret_bytes)?;
        let bytes = aead::seal(&secret, plaintext.as_bytes())?;
        Ok(ServerEncryptedBase64Message {
            message: base64::encode(&bytes),
        })
    }

    pub async fn encrypt_user_base64(
        &self,
        plaintext: &str,
    ) -> Result<UserEncryptedBase64Message, UnknownCryptoError> {
        let secret_bytes = crate::emoji::decode(&self.user_secret);
        let secret = SecretKey::from_slice(&secret_bytes)?;
        let bytes = aead::seal(&secret, plaintext.as_bytes())?;
        Ok(UserEncryptedBase64Message {
            message: base64::encode(&bytes),
        })
    }

    pub fn decrypt_encoded_header_with_slice(secret_slice: &[u8], message: &str) -> String {
        let enc_bytes = base64::decode(message).unwrap();
        SharedKeyring::decrypt_bytes_from_slice(secret_slice, enc_bytes.as_slice())
    }

    pub fn encrypt_and_encode_header_with_slice(secret_slice: &[u8], plaintext: &str) -> String {
        let message_bytes = plaintext.as_bytes();
        let encrypted_bytes = SharedKeyring::encrypt_bytes_from_slice(secret_slice, message_bytes);
        base64::encode_config(&encrypted_bytes, base64::URL_SAFE_NO_PAD)
    }
}
