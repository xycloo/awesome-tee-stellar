use blst::min_pk as bls;
use common::{
    message::{MessageKind, NetworkingMessage},
    networking::{Inbound, Outbound, build_overlay},
};
use tokio::sync::broadcast;

pub struct Executor {
    overlay_broadcast_tx: Option<broadcast::Sender<Outbound>>,

    /// optional to reduce spam on Executor.
    pub allowed_executors: Vec<bls::PublicKey>,
}

impl Executor {
    pub fn new() -> Self {
        Self {
            overlay_broadcast_tx: None,
            allowed_executors: Vec::new(),
        }
    }

    fn set_overlay_broadcast_tx(&mut self, overlay_broadcast_tx: broadcast::Sender<Outbound>) {
        self.overlay_broadcast_tx = Some(overlay_broadcast_tx);
    }

    #[cfg(not(feature = "allow_all_executors"))]
    fn is_signer_allowed(&self, signer: Vec<u8>) -> anyhow::Result<bool> {
        let public_key = PublicKey::from_slice(&signer)?;
        Ok(self.allowed_executors.contains(&public_key))
    }

    #[cfg(feature = "allow_all_executors")]
    fn is_signer_allowed(&self, _signer: Vec<u8>) -> anyhow::Result<bool> {
        Ok(true)
    }

    pub async fn worker(&mut self) -> anyhow::Result<()> {
        let (mut overlay_incoming_receiver, overlay_broadcast_tx, mut overlay) =
            build_overlay(vec![
                "chainevent".into(),
                "chainstate".into(),
                "executorchainevent".into(),
            ])?;
        self.set_overlay_broadcast_tx(overlay_broadcast_tx);

        tokio::spawn(async move {
            if let Err(e) = overlay.worker().await {
                tracing::error!("error on overlay worker: {:?}", e);
            }
        });

        while let Some(new_overlay_message) = overlay_incoming_receiver.recv().await {
            self.handle_overlay_message(new_overlay_message)
                .await
                .unwrap()
        }

        Ok(())
    }

    async fn handle_overlay_message(&mut self, message: Inbound) -> anyhow::Result<()> {
        let message: NetworkingMessage = bitcode::deserialize(&message.data)?;

        if !self.is_signer_allowed(message.signer())? {
            anyhow::bail!("signer not allowed, needs to attest first");
        }

        match &message.inner() {
            MessageKind::ExecutorChainEvent(_) => (),
            MessageKind::ExecutorChainStateResponse(_) => (),
            _ => (),
        }

        Ok(())
    }
}
