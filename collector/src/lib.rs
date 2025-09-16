use blst::min_pk as bls;
use common::{
    crypto::SigCombiner,
    message::{
        AggregateSignatureData, ChainStateRequest, MessageKind, NetworkingMessage, ToSigningHash,
    },
    networking::{Inbound, Multiaddr, Outbound, Reference, build_overlay},
};
use std::collections::HashMap;
use tokio::sync::broadcast;

use crate::committee::ThresholdRules;

mod committee;

pub struct PendingThresholdData<C: SigCombiner> {
    message: Outbound,
    rules: ThresholdRules<C>,
}

pub struct Collector<C: SigCombiner> {
    overlay_broadcast_tx: Option<broadcast::Sender<Outbound>>,

    pub committee_signers: Vec<bls::PublicKey>,

    pub pending_threshold: HashMap<[u8; 32], PendingThresholdData<C>>,

    /// optional to reduce spam on collector.
    pub allowed_executors: Vec<bls::PublicKey>,
}

impl<C: SigCombiner> Collector<C> {
    pub fn new(committee_signers: Vec<bls::PublicKey>) -> Self {
        Self {
            committee_signers,
            overlay_broadcast_tx: None,
            allowed_executors: Vec::new(),
            pending_threshold: HashMap::new(),
        }
    }

    fn set_overlay_broadcast_tx(&mut self, overlay_broadcast_tx: broadcast::Sender<Outbound>) {
        self.overlay_broadcast_tx = Some(overlay_broadcast_tx);
    }

    // todo: adapt
    #[cfg(not(feature = "allow_all_executors"))]
    fn is_signer_allowed(&self, signer: Vec<u8>) -> anyhow::Result<bool> {
        Ok(true)
    }

    fn is_committee_member(&self, signer: &[u8]) -> anyhow::Result<bool> {
        let pk = bls::PublicKey::from_bytes(signer)
            .map_err(|e| anyhow::anyhow!("invalid bls pk bytes: {:?}", e))?;
        Ok(self.committee_signers.contains(&pk))
    }

    #[cfg(feature = "allow_all_executors")]
    fn is_signer_allowed(&self, _signer: Vec<u8>) -> anyhow::Result<bool> {
        Ok(true)
    }

    pub async fn worker(&mut self, connect_to: Vec<Multiaddr>) -> anyhow::Result<()> {
        let (mut overlay_incoming_receiver, overlay_broadcast_tx, mut overlay) =
            build_overlay(vec![
                "chainevent".into(),
                "chainstate".into(),
                "executorchainevent".into(),
            ])?;

        for peer in connect_to {
            overlay.connect(&peer).unwrap();
        }

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
        let reqresp_reference = message.reference;
        tracing::info!("data hex is {:?}", hex::encode(&message.data));
        let mut message: NetworkingMessage = bincode::deserialize(&message.data).unwrap();

        // verify that the signature is correct. For nodes we really just want to verify that the request is coming
        // from a real executor TEE. This way we can prevent some (not all, depends on the executor's measurements) abuse to the API.
        //
        // NB: the collectors simply forward request contents so we're not expecting collector signer or signature in the payload.
        message.verify()?;

        if !self.is_signer_allowed(message.signer())? {
            anyhow::bail!("signer not allowed, needs to attest first");
        }

        match &message.inner() {
            MessageKind::ChainEvent(evt) => {
                message.set_inner(MessageKind::ExecutorChainEvent(
                    AggregateSignatureData::new(evt.clone(), vec![], vec![]),
                ));
                self.chain_event_cache_lookup(message).await?
            }
            MessageKind::CollectorChainStateResponse(resp) => {
                let reference = resp.reference;
                message.set_inner(MessageKind::ExecutorChainStateResponse(
                    AggregateSignatureData::new(resp.kind.clone(), vec![], vec![]),
                ));
                self.chain_state_response_cache_lookup(reference, message)
                    .await
                    .unwrap();
            }
            MessageKind::ExecutorChainStateRequest(req) => {
                let reference =
                    reqresp_reference.expect("inbound executor requests must contain reference");
                message.set_inner(MessageKind::CollectorChainStateRequest(
                    ChainStateRequest::new(reference, req.clone()),
                ));

                self.forward_to_overlay(message).await.unwrap();
            }
            _ => (),
        }

        Ok(())
    }

    pub async fn chain_state_response_cache_lookup(
        &mut self,
        reference: Reference,
        message: NetworkingMessage,
    ) -> anyhow::Result<()> {
        let signature = message.signature();
        let signer = message.signer();

        if !self.is_committee_member(&signer)? {
            tracing::info!("not part of the committee, ignoring");
            return Ok(());
        }

        let state_payload_hash = message.inner().compute_hash()?;
        let outbound = Outbound::direct_response(message, reference)?;

        self.push_to_pending_and_check(outbound, signer, signature, state_payload_hash)
            .await?;

        Ok(())
    }

    pub async fn chain_event_cache_lookup(
        &mut self,
        message: NetworkingMessage,
    ) -> anyhow::Result<()> {
        let signature = message.signature();
        let signer = message.signer();
        let state_payload_hash = message.inner().compute_hash()?;
        let outbound = Outbound::from_message_and_topics(vec!["chainstate".into()], message)?;

        self.push_to_pending_and_check(outbound, signer, signature, state_payload_hash)
            .await?;

        Ok(())
    }

    pub async fn push_to_pending_and_check(
        &mut self,
        outbound: Outbound,
        signer: Vec<u8>,
        signature: Vec<u8>,
        state_payload_hash: [u8; 32],
    ) -> anyhow::Result<()> {
        let (reached, outbound) = {
            let entry = self
                .pending_threshold
                .entry(state_payload_hash)
                .or_insert_with(|| PendingThresholdData {
                    message: outbound.clone(),
                    rules: ThresholdRules::new(self.committee_signers.len() - 1),
                });

            let (_count, _required, reached) = entry.rules.add_signature(signer, &signature)?;

            let aggregate = entry.rules.aggregated().ok_or(anyhow::anyhow!(
                "we expect to have the aggregate at this point"
            ))?;
            let signers = entry.rules.participating_signers();

            let mut outbound = entry.message.clone();
            let mut message: NetworkingMessage = bincode::deserialize(&outbound.data)?;
            let mut inner = message.inner();

            match &mut inner {
                MessageKind::ExecutorChainEvent(agg) => {
                    agg.aggregated_signature = aggregate.to_vec();
                    agg.signers = signers;
                }

                MessageKind::ExecutorChainStateResponse(agg) => {
                    agg.aggregated_signature = aggregate.to_vec();
                    agg.signers = signers;
                }

                _ => (),
            }

            message.set_inner(inner);
            outbound.data = bincode::serialize(&message)?;

            (reached, outbound)
        };

        if reached {
            self.send_outbound(outbound).await?;
            self.pending_threshold.remove(&state_payload_hash);
        }

        Ok(())
    }

    async fn forward_to_overlay(&mut self, message: NetworkingMessage) -> anyhow::Result<()> {
        self.overlay_broadcast_tx
            .as_ref()
            .ok_or(anyhow::anyhow!("overlay broadcast sender not set in self"))?
            .send(Outbound::from_message_and_topics(
                vec!["chainstate".into()],
                message,
            )?)?;
        Ok(())
    }

    async fn send_outbound(&self, outbound: Outbound) -> anyhow::Result<()> {
        let _ = self
            .overlay_broadcast_tx
            .as_ref()
            .ok_or(anyhow::anyhow!("overlay broadcast sender not set in self"))?
            .send(outbound)?;
        Ok(())
    }
}
