use crate::blake::SmallBlakeHasher;
use crate::encoders::EncodedBytesFn;
use crate::shapes::*;

pub struct EmojiHash {}

impl EmojiHash {
    pub fn digest(message: &[u8]) -> EncodedBytes {
        let hashcode = SmallBlakeHasher::Blake2b32
            .digest(message)
            .expect("can get blake-32");

        EncodedBytes {
            encoded: crate::emoji::encode(hashcode.as_ref().to_vec().as_slice()),
            codec: EmojiCryptCodec::EmojiEncoded,
        }
    }
}

pub struct ChecksummingEncoder {}
impl ChecksummingEncoder {
    pub fn encode_with_checksum_and_source(
        codec: EmojiCryptCodec,
        message: &[u8],
        source: &[u8],
    ) -> EncodedMessageWithChecksum {
        let encoded = match codec {
            EmojiCryptCodec::EmojiEncoded => EncodedBytesFn::emoji_encode(message),
            EmojiCryptCodec::Base64 => EncodedBytesFn::base64_encode(message),
            EmojiCryptCodec::Base64Websafe => EncodedBytesFn::base64_websafe_encode(message),
        };

        EncodedMessageWithChecksum {
            message: encoded,
            hash: EmojiHash::digest(source),
        }
    }

    pub fn emoji_encode_with_checksum(message: &[u8]) -> EncodedMessageWithChecksum {
        ChecksummingEncoder::encode_with_checksum_and_source(
            EmojiCryptCodec::EmojiEncoded,
            message,
            message,
        )
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn encoding_and_checksums_are_equal() {
        let message_a = "foo";
        let message_b = "bar";

        let crypt_a = ChecksummingEncoder::emoji_encode_with_checksum(message_a.as_bytes());
        let crypt_a_prime = ChecksummingEncoder::emoji_encode_with_checksum(message_a.as_bytes());

        let crypt_b = ChecksummingEncoder::emoji_encode_with_checksum(message_b.as_bytes());
        let crypt_b_prime = ChecksummingEncoder::emoji_encode_with_checksum(message_b.as_bytes());

        //        let emoji_message = EmojiEncodedString::from("hello")

        println!("{} @ {}", crypt_a.message.encoded, crypt_a.hash.encoded);

        assert_eq!(crypt_a.message.encoded, crypt_a_prime.message.encoded);
        assert_eq!(crypt_a.hash.encoded, crypt_a_prime.hash.encoded);

        assert_eq!(crypt_b.message.encoded, crypt_b_prime.message.encoded);
        assert_eq!(crypt_b.hash.encoded, crypt_b_prime.hash.encoded);

        assert_ne!(crypt_a.message.encoded, crypt_b.message.encoded);
        assert_ne!(crypt_a.hash.encoded, crypt_b.hash.encoded);
    }
}
