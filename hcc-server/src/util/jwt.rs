

use tide::prelude::*;
use super::encryption::{EncryptedKeyring, SharedKeyring, UserEncryptedMessage};

use jsonwebtokens::{encode, Algorithm, AlgorithmID, Verifier};

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

fn blake_hash_to_secret(bytes: Vec<u8>) -> Vec<u8> {

    // reduce the 128 bytes of the blake hash into 32 bytes for our initial handshake key...
    // do not store this anywhere, just rely on this code to run
    // "middle-out" key extraction

    assert_eq!(128, bytes.len());

    let bytes_head = bytes.clone().into_iter();
    let bytes_head_b = bytes_head.clone().skip(1);

    let bytes_tail = bytes.clone().into_iter().rev();
    let bytes_tail_b = bytes_tail.clone().skip(1);

    let heads = bytes_head.step_by(2).zip(
        bytes_head_b.step_by(2).rev()
    );

    let tails = bytes_tail.step_by(2).zip(
        bytes_tail_b.step_by(2).rev()
    );

    let heads_items = heads.take(8).flat_map(|x| vec![x.0, x.1]);

    let tails_items = tails.take(8).flat_map(|x| vec![x.0, x.1]);

    heads_items.rev().zip(tails_items).flat_map(|x| vec![x.0, x.1]).collect()
}

impl JsonWebTokenUtil {

    
    pub fn verify_auth_token(
        self: &JsonWebTokenUtil, token_str: &str, email: &str) -> Result<serde_json::value::Value, jsonwebtokens::error::Error> {
            
        let pem_data = &self.secrets.pub_key_pem_data[..];

        let alg = Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, pem_data)?;

        let verifier = Verifier::create().issuer(&self.issuer).string_equals("email", email).build()?;

        verifier.verify(&token_str, &alg)
    }

    pub fn sign_auth_token(self: &JsonWebTokenUtil, email: &str) -> Result<String, jsonwebtokens::error::Error> {
        let pem_data = &self.secrets.key_pem_data[..];

        let alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, pem_data)?;
        let header = json!({ "alg": alg.name() });
        let now = chrono::Utc::now().timestamp();
        let twentyfour_hr_millis = self.expiry_duration_millis;
        let exp = now + twentyfour_hr_millis;
        let claims = json!({ "iss": &self.issuer, "exp": exp, "email": &email });
        
        encode(&header, &claims, &alg)
    }

    pub fn encode_pubkey( self: &JsonWebTokenUtil) -> String {
        hex::encode(&self.secrets.pub_key_pem_data)
    }

    pub fn verify_csrf_token(
        self: &JsonWebTokenUtil,
        token_str: &str,
        session_id: &str,
        secrets: &SharedKeyring
    ) -> Result<serde_json::value::Value, jsonwebtokens::error::Error> {

        let pem_data = &self.secrets.pub_key_pem_data[..];

        let alg = Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, pem_data)?;

        let sid = Hasher::Blake2b512.digest(session_id.as_bytes()).expect("blake digest");
        let sid_hex = hex::encode(sid.as_ref());

        let message = UserEncryptedMessage {
            sender: secrets.user.clone(),
            message: token_str.to_owned()
        };

        let decrypted = message.decrypt(secrets).expect("can decrypt csrf");

        let verifier = Verifier::create().issuer(&self.issuer).string_equals("sid", sid_hex).build()?;

        let res = verifier.verify(&decrypted, &alg)?;

        Ok(res)
    }

    pub fn sign_csrf_token(self: &JsonWebTokenUtil, session_id: &str, keyring: &SharedKeyring) -> Result<String, jsonwebtokens::error::Error> {
       
        // use our secret key to sign some data for the client:

        // provide the bootstrap key-signing credentials in this handshake
        // we will expect all subsequent comminications to be encrypted with the keyring 
        
        // right now the user needs to be able to decrypt the encrypted keyring... 
        // how will we determine our shared handshake key? for now we will just use the hashed SID as our slice

        let pem_data = &self.secrets.key_pem_data[..];

        let sid = Hasher::Blake2b512.digest(session_id.as_bytes()).expect("blake digest");
        let sid_hex = hex::encode(sid.as_ref());

        let keyr: EncryptedKeyring = EncryptedKeyring::encrypt_with_secret(keyring, &blake_hash_to_secret(sid_hex.as_bytes().to_owned())).expect("encrypted key ring");

        let alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, pem_data)?;
        let header = json!({ "alg": alg.name() });
        let now = chrono::Utc::now().timestamp();
        let twentyfour_hr_millis = self.expiry_duration_millis;
        let exp = now + twentyfour_hr_millis;
        let claims = json!({ "iss": &self.issuer, "exp": exp, "sid": sid_hex, "keyring": keyr });

        encode(&header, &claims, &alg)
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
