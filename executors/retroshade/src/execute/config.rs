use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize, Clone)]
pub struct Config {
    pub network: String,
    pub untrusted_node_address: String,
    pub database_conn: String,
}

pub async fn get_network_id_from_env() -> [u8; 32] {
    let project_definition = tokio::fs::read_to_string("./config/executor.toml")
        .await
        .unwrap();
    let config: Config = toml::from_str(&project_definition).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&config.network);
    hasher.finalize().as_slice().try_into().unwrap()
}
