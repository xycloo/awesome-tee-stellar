use stellar::*;

#[tokio::main]
async fn main() {
    let client = StellarClient::new("127.0.0.1:8085".into());
    let key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

    let node = client.client_from_self(key);
}
