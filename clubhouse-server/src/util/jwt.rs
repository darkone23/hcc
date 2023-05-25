use clubhouse_core::emoji;
use tide::prelude::*;

use jsonwebtokens::{Algorithm, AlgorithmID, Verifier};
use clubhouse_core::shapes::{ClientServerKeyring, EncryptedKeyring, TopSecretSharedKeyring};
use clubhouse_core::encryption::{EmojiCrypt, EncryptionFunctions};

use orion::hazardous::hash::blake2::blake2b::Hasher;


/*

// begin JWT auth stuff

// https://blog.logrocket.com/how-to-secure-a-rest-api-using-jwt-7efd83e71432/


#from https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9

ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
# Don't add passphrase
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
cat jwtRS256.key
cat jwtRS256.key.pub

*/

#[derive(Clone)]
pub struct JsonWebTokenUtil {
    pub secrets: JsonWebTokenSecrets,
    pub issuer: String,
    pub expiry_duration_millis: i64,
}

impl JsonWebTokenUtil {
    pub fn verify_auth_token(
        self: &JsonWebTokenUtil,
        jwt_claims: &str,
        email: &str,
    ) -> Result<serde_json::value::Value, jsonwebtokens::error::Error> {
        let pem_data = &self.secrets.pub_key_pem_data[..];

        let alg = Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, pem_data)?;

        let verifier = Verifier::create()
            .issuer(&self.issuer)
            .string_equals("email", email)
            .build()?;

        verifier.verify(&jwt_claims, &alg)
    }

    pub fn sign_auth_token(
        self: &JsonWebTokenUtil,
        email: &str,
    ) -> Result<String, jsonwebtokens::error::Error> {
        let pem_data = &self.secrets.key_pem_data[..];

        let alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, pem_data)?;
        let header = json!({ "alg": alg.name() });
        let now = chrono::Utc::now().timestamp();
        let twentyfour_hr_millis = self.expiry_duration_millis;
        let exp = now + twentyfour_hr_millis;
        let claims = json!({ "iss": &self.issuer, "exp": exp, "email": &email });

        // base64 websafe encode
        jsonwebtokens::encode(&header, &claims, &alg)
    }

    pub fn verify_csrf_token(
        self: &JsonWebTokenUtil,
        jwt_claims: &str,
        session_id: &str,
    ) -> Result<serde_json::value::Value, jsonwebtokens::error::Error> {
        let pem_data = &self.secrets.pub_key_pem_data[..];

        let alg = Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, pem_data)?;

        let sid = Hasher::Blake2b512
            .digest(session_id.as_bytes())
            .expect("blake digest");

        let sid_hex = emoji::encode(sid.as_ref());

        let verifier = Verifier::create()
            .issuer(&self.issuer)
            .string_equals("sid", sid_hex)
            .build()?;

        let res = verifier.verify(&jwt_claims, &alg)?;

        Ok(res)
    }

    pub fn sign_csrf_token(
        self: &JsonWebTokenUtil,
        session_id: &str,
        keyring: &ClientServerKeyring,
    ) -> Result<String, jsonwebtokens::error::Error> {
        // use our secret key to sign some data for the client:

        // provide the bootstrap key-signing credentials in this handshake
        // we will expect all subsequent comminications to be encrypted with the keyring

        // right now the user needs to be able to decrypt the encrypted keyring...
        // how will we determine our shared handshake key? for now we will just use the hashed SID as our slice

        let pem_data = &self.secrets.key_pem_data[..];

        let sid = Hasher::Blake2b512
            .digest(session_id.as_bytes())
            .expect("blake digest");

        let sid_hex = emoji::encode(sid.as_ref());

        let session_secret = EmojiCrypt::derive_session_secret(
            sid_hex.as_bytes().to_owned()
        );

        // wire format for shared keyring
        let shared_keyring = TopSecretSharedKeyring {
            a: keyring.server.sender_emoji_id.to_owned(),
            b: keyring.client.sender_emoji_id.to_owned(),
            x: emoji::encode(keyring.server.secret.as_slice()),
            y: emoji::encode(keyring.client.secret.as_slice()),
        };

        let message = serde_json::to_string(&shared_keyring).expect("serialize");

        let encrypted_bytes = EncryptionFunctions::seal(session_secret.as_slice(), message.as_bytes());

        let keyr = EncryptedKeyring {
            b: emoji::encode(encrypted_bytes.as_slice()),
        };

        let alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, pem_data)?;
        let header = json!({ "alg": alg.name() });
        let now = chrono::Utc::now().timestamp();
        let twentyfour_hr_millis = self.expiry_duration_millis;
        let exp = now + twentyfour_hr_millis;
        let claims = json!({ "iss": &self.issuer, "exp": exp, "sid": sid_hex, "keyring": keyr });

        // base64 websafe encode
        jsonwebtokens::encode(&header, &claims, &alg)
    }
}

#[derive(Clone)]
pub struct JsonWebTokenSecrets {
    key_pem_data: Vec<u8>,
    pub_key_pem_data: Vec<u8>,
}

impl JsonWebTokenSecrets {
    pub fn read_keys(key_path: &str, pubkey_path: &str) -> JsonWebTokenSecrets {
        let key_bytes = std::fs::read(key_path).expect("Unable to load RSA key file.");
        let pubkey_bytes = std::fs::read(pubkey_path).expect("Unable to load RSA public key file.");

        JsonWebTokenSecrets {
            key_pem_data: key_bytes,
            pub_key_pem_data: pubkey_bytes,
        }
    }
}
