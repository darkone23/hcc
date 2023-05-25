use crate::shapes::*;

pub struct EncodedBytesFn {}
impl EncodedBytesFn {
    pub fn base64_encode(message: &[u8]) -> EncodedBytes {
        EncodedBytes {
            encoded: crate::base64::encode_basic(message).encoded,
            codec: EmojiCryptCodec::Base64,
        }
    }

    pub fn base64_websafe_encode(message: &[u8]) -> EncodedBytes {
        EncodedBytes {
            encoded: crate::base64::encode_websafe(message).encoded,
            codec: EmojiCryptCodec::Base64Websafe,
        }
    }

    pub fn emoji_encode(message: &[u8]) -> EncodedBytes {
        EncodedBytes {
            encoded: crate::emoji::encode(message),
            codec: EmojiCryptCodec::EmojiEncoded,
        }
    }
}
