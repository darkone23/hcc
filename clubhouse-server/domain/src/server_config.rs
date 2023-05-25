#[derive(Clone)]
pub struct ServerConfig {
    pub domain: String,
    pub session_cookie_name: String,
    pub session_ttl_hours: u32,
    pub encryption_key_emoji: String,
    pub rsa_private_key_path: String,
    pub rsa_public_key_path: String,
    pub sql_connection_url: String,
    pub bind_url: String,
    pub super_user_email: String,
    pub super_user_pwhash_emoji: String,
    pub client_dist_dir: String,
}
