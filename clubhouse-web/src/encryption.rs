use clubhouse_core::base64;
use clubhouse_core::encryption::EmojiCrypt;
use clubhouse_core::shapes::{
    ClientServerKeyring, EmojiCryptCodec, EncryptedKeyring, SenderType, TopSecretSharedKeyring,
};
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
    __keyring: ClientServerKeyring,
}

#[wasm_bindgen]
impl ClientKeyring {
    #[wasm_bindgen(constructor)]
    pub fn new(decrypted_secrets: JsValue) -> ClientKeyring {
        let convert: TopSecretSharedKeyring =
            serde_wasm_bindgen::from_value(decrypted_secrets).unwrap();

        let keyring = EmojiCrypt::decode_keyring(&convert);

        ClientKeyring { __keyring: keyring }
    }

    pub fn decrypt(&self, encrypted: &str) -> String {
        let keyring = &self.__keyring;
        let decrypted = EmojiCrypt::decrypt(
            keyring,
            encrypted,
            EmojiCryptCodec::EmojiEncoded,
            SenderType::Server,
        );
        String::from_utf8(decrypted).expect("invalid utf8")
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        let keyring = &self.__keyring;

        EmojiCrypt::encrypt(
            keyring,
            EmojiCryptCodec::EmojiEncoded,
            SenderType::Client,
            plaintext.as_bytes(),
        )
        .encrypted_message
    }

    pub fn handle_jwt_challenge(&self, header: &str) -> String {
        let keyring = &self.__keyring;

        let decrypted = EmojiCrypt::decrypt(
            keyring,
            header,
            EmojiCryptCodec::Base64Websafe,
            SenderType::Server,
        );

        let response = EmojiCrypt::encrypt_base64websafe_client(keyring, decrypted.as_slice());

        response.encrypted_message
    }

    pub fn handle_csrf_challenge(&self, csrf_token: &str) -> String {
        let keyring = &self.__keyring;
        let response = EmojiCrypt::encrypt_base64websafe_client(keyring, csrf_token.as_bytes());

        response.encrypted_message
    }

    pub fn empty() -> ClientKeyring {
        ClientKeyring {
            __keyring: ClientServerKeyring::empty(),
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
    let try_decode = base64::decode_websafe(claims);
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
        let secret_slice = EmojiCrypt::derive_session_secret(claims_json.sid.as_bytes().to_owned());

        let message = clubhouse_core::emoji::decode(&claims_json.keyring.b);

        let secret: SecretKey = SecretKey::from_slice(&secret_slice).unwrap();

        let bytes = aead::open(&secret, &message).unwrap();

        let json = String::from_utf8(bytes).unwrap();

        parse(&json)
    } else {
        parse("{}")
    }
}
