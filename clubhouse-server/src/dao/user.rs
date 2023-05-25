use crate::wiring::ServerWiring;
use clubhouse_core::checksum::EmojiHash;
use clubhouse_core::shapes::EmojiCryptMessage;
use domain::server_config::ServerConfig;

use domain::sea_orm::entities::prelude::UserEmailPassword;
use domain::sea_orm::entities::user_email_password;

use sea_orm::*;

pub struct UserDao {}

impl UserDao {
    pub async fn find_by_email(
        wiring: &ServerWiring,
        email_plaintext_bytes: &[u8],
    ) -> Result<Option<user_email_password::Model>, ()> {
        let email_hash: &str = &EmojiHash::digest(email_plaintext_bytes).encoded;
            
        let matches_email = user_email_password::Column::EmailHash.eq(email_hash);

        let res = UserEmailPassword::find()
            .filter(matches_email)
            .limit(1)
            .one(&wiring.db)
            .await;

        if res.is_ok() {
            let i = res.unwrap();
            Ok(i)
        } else {
            Err(())
        }
    }

    pub async fn insert_super_user(config: &ServerConfig, wiring: &ServerWiring) -> Result<(), ()> {
        let plaintext_login = &config.super_user_email.as_bytes();

        let already_exists = Self::find_by_email(wiring, plaintext_login).await.unwrap();

        if already_exists.is_some() {
            tide::log::info!("super user already exists!");
        } else {
            tide::log::info!("super user does not exist!");

            let emoji_key = &config.encryption_key_emoji;                
            let emoji_secret = clubhouse_core::emoji::decode(emoji_key);

            let hash: &str = &EmojiHash::digest(plaintext_login).encoded;
            let encrypted = clubhouse_core::encryption::EncryptionFunctions::seal(&emoji_secret, plaintext_login);

            let encrypted_email = String::from(clubhouse_core::emoji::encode(encrypted.as_slice()));
            let email_hash = String::from(hash.clone());

            let encoded_hash = String::from(config.super_user_pwhash_emoji.clone());

            let s = user_email_password::ActiveModel {
                email: Set(encrypted_email),
                email_hash: Set(email_hash),
                password: Set(encoded_hash),
                active: Set(true),
                ..Default::default()
            };

            let operation = UserEmailPassword::insert(s).exec(&wiring.db).await;

            if operation.is_ok() {
                let item = operation.ok();
                println!("INSERTED ONE: {:?}", item);
            } else {
                println!(
                    "Failed to insert super user... maybe it already exists?? {:?}",
                    operation.err()
                );
            }
        }

        Ok(())
    }
}
