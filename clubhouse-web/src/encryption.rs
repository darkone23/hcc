use clubhouse_core::encryption::{EncryptedKeyring, SharedKeyring, TopSecretSharedKeyring};
use serde::{Deserialize, Serialize};

use orion::aead;
use orion::kex::SecretKey;

use wasm_bindgen::prelude::*;

macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => ("", ""),
        }
    }};
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonClaims {
    exp: i32,
    iss: String,
    keyring: EncryptedKeyring,
    sid: String,
}

#[wasm_bindgen]
pub struct ClientKeyring {
    broadcast_secret: Vec<u8>,
    user_secret: Vec<u8>,
}

#[wasm_bindgen]
impl ClientKeyring {
    #[wasm_bindgen(constructor)]
    pub fn new(decrypted_secrets: JsValue) -> ClientKeyring {
        let convert: TopSecretSharedKeyring =
            serde_wasm_bindgen::from_value(decrypted_secrets).unwrap();

        ClientKeyring {
            broadcast_secret: clubhouse_core::emoji::decode(&convert.x),
            user_secret: clubhouse_core::emoji::decode(&convert.y),
        }
    }

    pub fn decrypt(&self, encrypted: &str) -> String {
        SharedKeyring::decrypt_emoji_from_slice(&self.broadcast_secret, encrypted)
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        SharedKeyring::encrypt_emoji_from_slice(&self.user_secret, plaintext)
    }

    pub fn handle_jwt_challenge(&self, header: &str) -> String {
        let challenge =
            SharedKeyring::decrypt_encoded_header_with_slice(&self.broadcast_secret, header);

        SharedKeyring::encrypt_and_encode_header_with_slice(&self.user_secret, &challenge)
    }

    pub fn handle_csrf_challenge(&self, csrf_token: &str) -> String {
        SharedKeyring::encrypt_and_encode_header_with_slice(&self.user_secret, csrf_token)
    }

    pub fn empty() -> ClientKeyring {
        Self {
            broadcast_secret: vec![],
            user_secret: vec![],
        }
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace=JSON)]
    pub fn parse(message: &str) -> JsValue;

    // pub fn atob(message: &str) -> String;
}

fn decode_jwt_claims(jwt_payload: &str) -> JsonClaims {
    // decode jwt payload into parts
    let (_signature, message) = expect_two!(jwt_payload.rsplitn(2, '.'));
    let (_header, claims) = expect_two!(message.splitn(2, '.'));
    let try_decode = base64::decode_config(claims, base64::URL_SAFE_NO_PAD).unwrap();
    let extracted_json = String::from_utf8(try_decode).unwrap();
    let decoded = parse(&extracted_json);

    serde_wasm_bindgen::from_value(decoded).unwrap()
}

#[wasm_bindgen]
pub fn recv_claims(issuer: &str, csrf_signed: &str) -> JsValue {
    /* ---

    the encryption keyring is delivered over an encoded jwt payload
    the payload is encrypted using the session id as the key

       --- */

    let claims_json = decode_jwt_claims(csrf_signed);

    if claims_json.iss == issuer {
        let secret_slice = clubhouse_core::emoji::EmojiCrypt::derive_session_secret(
            claims_json.sid.as_bytes().to_owned(),
        );

        let message = clubhouse_core::emoji::decode(&claims_json.keyring.b);

        let secret: SecretKey = SecretKey::from_slice(&secret_slice).unwrap();

        let bytes = aead::open(&secret, &message).unwrap();

        let json = String::from_utf8(bytes).unwrap();

        parse(&json)
    } else {
        parse("{}")
    }
}
