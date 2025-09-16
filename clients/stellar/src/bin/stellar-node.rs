use stellar::*;
use tokio::runtime::Builder;

fn main() {
    tracing_subscriber::fmt::init();
    let rt = Builder::new_multi_thread().enable_all().worker_threads(4).build().unwrap();
    
    let client = StellarClient::new("127.0.0.1:8085".into(), "Test SDF Network ; September 2015".into());
    let key: [u8; 32] =
        hex::decode("14c65e7f01ad92298c396f0957bdf5b16e513b7302d2e84b8424a70d866ccfd4")
            .unwrap()
            .try_into()
            .unwrap();

    let mut node = client.client_from_self(&key).unwrap();
    let result = rt.block_on(node.start(vec![]));

    tracing::info!("{:?}", result);
}

#[cfg(test)]
mod test {
    use rand::random;

    #[test]
    fn key() {
        let key: [u8; 32] = random();
        let sk = blst::min_pk::SecretKey::key_gen(&key, &[]).expect("key_gen");

        println!("{}", hex::encode(sk.to_bytes()));

        let pk = sk.sk_to_pk();
        let pk_bytes: [u8; 48] = pk.to_bytes();
        println!("{}", hex::encode(pk_bytes));
    }
}
