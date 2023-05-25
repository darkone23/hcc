use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Base64Mode {
    Basic,
    WebSafe,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Base64Message {
    pub mode: Base64Mode,
    pub encoded: String,
}

pub fn encode_websafe(message: &[u8]) -> Base64Message {
    Base64Message {
        mode: Base64Mode::WebSafe,
        encoded: base64::encode_config(message, base64::URL_SAFE_NO_PAD),
    }
}

pub fn encode_basic(message: &[u8]) -> Base64Message {
    Base64Message {
        mode: Base64Mode::Basic,
        encoded: base64::encode(message),
    }
}

pub fn decode_websafe(encoded: &str) -> Vec<u8> {
    base64::decode_config(encoded, base64::URL_SAFE_NO_PAD).unwrap()
}

pub fn decode(encoded: &str) -> Vec<u8> {
    base64::decode(encoded).unwrap()
}
