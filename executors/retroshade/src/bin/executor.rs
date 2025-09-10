use blst::min_pk::PublicKey;
use retroshade_executor::*;

#[tokio::main]
async fn main() {
    let mut committee_signers = Vec::new();
    {
        let pubkey_hex = "816827a0e7abe5fd7c1c1dac37b33f50760bbb8b43ea7dd9e2730fac3437c2aaa699d609ac8cfca1def3971e1b9713af";
        let pubkey = PublicKey::from_bytes(&hex::decode(pubkey_hex).unwrap()).unwrap();
        committee_signers.push(pubkey);
    }

    let config = retroshade_executor::execute::config::Config {
        network: "Test SDF Network ; September 2015".into(),
        untrusted_node_address: "127.0.0.1:8085".into(),
        database_conn: "postgresql://postgres@localhost:5432/mercury_light_db".into(),
    };

    let mut executor = Executor::new(committee_signers, config).await.unwrap();
    let result = executor.worker(vec![todo!()]).await;

    tracing::info!("{:?}", result);
}
