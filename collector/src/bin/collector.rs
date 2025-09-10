use blst::min_pk::PublicKey;
use collector::*;
use common::crypto;

#[tokio::main]
async fn main() {
    let mut commitee_signers = Vec::new();
    {
        let pubkey_hex = "816827a0e7abe5fd7c1c1dac37b33f50760bbb8b43ea7dd9e2730fac3437c2aaa699d609ac8cfca1def3971e1b9713af";
        let pubkey = PublicKey::from_bytes(&hex::decode(pubkey_hex).unwrap()).unwrap();
        commitee_signers.push(pubkey);
    }

    let mut collector: Collector<crypto::BlstMinPkCombiner> = Collector::new(commitee_signers);
    let result = collector.worker(vec![todo!()]).await;
    tracing::info!("{:?}", result);
}
