use blst::min_pk as bls;
use common::{
    message::{
        ChainEventKind, ChainStateRequestKind, ChainStateResponse, ChainStateResponseKind,
        MessageKind, NetworkingMessage,
    },
    networking::{Inbound, Outbound, build_overlay},
};
use tokio::sync::{broadcast, mpsc};

pub struct CommitteeNode<B> {
    pub signing_key: bls::SecretKey,
    pub overlay_broadcast_tx: Option<broadcast::Sender<Outbound>>,
    pub allowed_executors: Vec<bls::PublicKey>,
    pub inner: B,
}

impl<B: BlockchainClient> CommitteeNode<B> {
    pub fn new(signing_key: &[u8; 32], client: B) -> anyhow::Result<Self> {
        let signing_key = bls::SecretKey::from_bytes(signing_key)
            .map_err(|e| anyhow::anyhow!("invalid BLS secret key bytes: {:?}", e))?;

        let node = Self {
            signing_key,
            inner: client,
            overlay_broadcast_tx: None,
            allowed_executors: Vec::new(),
        };

        Ok(node)
    }

    fn set_overlay_broadcast_tx(&mut self, overlay_broadcast_tx: broadcast::Sender<Outbound>) {
        self.overlay_broadcast_tx = Some(overlay_broadcast_tx);
    }

    // todo: adapt
    #[cfg(not(feature = "allow_all_executors"))]
    fn is_signer_allowed(&self, signer: Vec<u8>) -> anyhow::Result<bool> {
        Ok(true)
    }

    #[cfg(feature = "allow_all_executors")]
    fn is_signer_allowed(&self, _signer: Vec<u8>) -> anyhow::Result<bool> {
        Ok(true)
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        // first we start the client job
        let mut event_receiver = B::spawn_chain_event_worker()?;
        let (mut overlay_incoming_receiver, overlay_broadcast_tx, mut overlay) =
            build_overlay(vec!["chainevent".into(), "chainstate".into()])?;
        self.set_overlay_broadcast_tx(overlay_broadcast_tx);

        tokio::spawn(async move {
            if let Err(e) = overlay.worker().await {
                tracing::error!("error on overlay worker: {:?}", e);
            }
        });

        loop {
            tokio::select! {
                new_chain_event = event_receiver.recv() => {
                    if let Some(new_chain_event) = new_chain_event {
                        self.handle_chain_event(new_chain_event).await;
                    }
                }

                new_overlay_message = overlay_incoming_receiver.recv() => {
                    if let Some(new_overlay_message) = new_overlay_message {
                        let result = self.handle_overlay_message(new_overlay_message).await;
                        if let Err(e) = result {
                            tracing::error!("failed to handle inbound overlay message {:?}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_overlay_message(&mut self, message: Inbound) -> anyhow::Result<()> {
        let message: NetworkingMessage = bitcode::deserialize(&message.data)?;

        // verify that the signature is correct. For nodes we really just want to verify that the request is coming
        // from a real executor TEE. This way we can prevent some (not all, depends on the executor's measurements) abuse to the API.
        //
        // NB: the collectors simply forward request contents so we're not expecting collector signer or signature in the payload.
        message.verify()?;

        if !self.is_signer_allowed(message.signer())? {
            anyhow::bail!("signer not allowed, needs to attest first");
        }

        match message.inner() {
            MessageKind::CollectorChainStateRequest(requested_state) => {
                let result = self.inner.retrieve_chain_state(requested_state.kind)?;
                self.broadcast_overlay_message(
                    MessageKind::CollectorChainStateResponse(ChainStateResponse::new(
                        requested_state.reference,
                        result,
                    )),
                    "chainstate",
                )?;
            }
            _ => (),
        }

        Ok(())
    }

    fn broadcast_overlay_message(
        &mut self,
        message: MessageKind,
        topic: &str,
    ) -> anyhow::Result<()> {
        let message = NetworkingMessage::new(message, self.signing_key.clone())?;
        let outbound = Outbound::from_message_and_topics(vec![topic.into()], message)?;
        let overlay_broadcast_tx = self
            .overlay_broadcast_tx
            .as_ref()
            .ok_or(anyhow::anyhow!("broadcast channel not found"))?;
        overlay_broadcast_tx.send(outbound)?;
        Ok(())
    }

    async fn handle_chain_event(&mut self, new_chain_event: ChainEventKind) {
        let kind = MessageKind::ChainEvent(new_chain_event);
        if let Err(e) = self.broadcast_overlay_message(kind, "chainevent") {
            tracing::info!("failed to handle chain event {:?}", e);
        }
    }
}

pub trait BlockchainClient {
    fn spawn_chain_event_worker() -> anyhow::Result<mpsc::Receiver<ChainEventKind>>;

    fn retrieve_chain_state(
        &self,
        requested_state: ChainStateRequestKind,
    ) -> anyhow::Result<ChainStateResponseKind>;
}
