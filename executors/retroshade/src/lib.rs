use blst::min_pk as bls;
use common::{
    message::{
        AggregateSignatureData, ChainEventKind, ChainStateResponseKind, MessageKind,
        NetworkingMessage, ToSigningHash,
    },
    networking::{Inbound, Multiaddr, Outbound, build_overlay},
};
use sha2::{Digest, Sha256};
use stellar_xdr::next::{Limits, ReadXdr};
use tokio::sync::broadcast;

use crate::execute::{ConstructedZephyrBinary, db::PgConnection};

pub mod execute;

pub struct Executor {
    overlay_broadcast_tx: Option<broadcast::Sender<Outbound>>,

    // nb: this should be inferred from measured config.
    pub committee_signers: Vec<bls::PublicKey>,

    /// connection to the connected database
    pub db: PgConnection,

    /// retorshade binaries that were deployed prior to starting the node
    pub retroshade_contracts: Vec<ConstructedZephyrBinary>,

    /// http api from an untrusted node used for optimistic execution.
    untrusted_node_address: String,

    /// stellar network.
    network: [u8; 32],
}

impl Executor {
    pub async fn new(
        committee_signers: Vec<bls::PublicKey>,
        config: execute::config::Config,
    ) -> anyhow::Result<Self> {
        let db = PgConnection::new(&config.database_conn).await?;
        let mut hasher = Sha256::new();

        hasher.update(&config.network);
        let network = hasher.finalize().as_slice().try_into().unwrap();
        let executor = Self {
            overlay_broadcast_tx: None,
            committee_signers,
            db,
            untrusted_node_address: config.untrusted_node_address,
            retroshade_contracts: vec![],
            network,
        };

        Ok(executor)
    }

    fn set_overlay_broadcast_tx(&mut self, overlay_broadcast_tx: broadcast::Sender<Outbound>) {
        self.overlay_broadcast_tx = Some(overlay_broadcast_tx);
    }

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
        self.load_retroshade_contracts().await;

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
        let message: NetworkingMessage = bincode::deserialize(&message.data)?;

        if !self.is_signer_allowed(message.signer())? {
            anyhow::bail!("signer not allowed, needs to attest first");
        }

        match &message.inner() {
            MessageKind::ExecutorChainEvent(evt) => self.execute_close_meta(evt).await?,
            MessageKind::ExecutorChainStateResponse(state) => {
                self.hanlde_commitee_state_response(state).await?
            }
            _ => (),
        }

        Ok(())
    }

    async fn load_retroshade_contracts(&mut self) {
        let client = &self.db.client;

        let retroshade_contracts = {
            let binaries = execute::db::read_binaries(client).await;
            if let Ok(constructed_binaries) = binaries {
                let mut mercury_contracts = Vec::new();

                for program in constructed_binaries {
                    if program.is_retroshade {
                        mercury_contracts.push(program.clone())
                    }
                }

                mercury_contracts
            } else {
                tracing::warn!("No retroshade binaries found: {:?}", binaries);
                vec![]
            }
        };

        self.retroshade_contracts = retroshade_contracts;
    }

    fn verify_aggregated_signature<T: ToSigningHash>(
        &mut self,
        payload: &AggregateSignatureData<T>,
    ) -> anyhow::Result<()> {
        if payload.signers.len() < self.committee_signers.len() - 1 {
            anyhow::bail!("threshold invalid");
        }
        
        for signer in &payload.signers {
            if !self.is_committee_member(signer)? {
                tracing::info!(
                    "got aggregated payload which contains non committee member {:?}, skipping this event.",
                    signer
                );
                anyhow::bail!("non committee member");
            }
        }

        payload.verify()?;

        Ok(())
    }

    async fn execute_close_meta(
        &mut self,
        evt: &AggregateSignatureData<ChainEventKind>,
    ) -> anyhow::Result<()> {
        self.verify_aggregated_signature(evt)?;
        
        let meta = match &evt.inner {
            ChainEventKind::LedgerClose(meta) => meta.meta.clone(),
        };
        let meta = stellar_xdr::next::LedgerCloseMeta::from_xdr(&meta, Limits::none()).unwrap();

        self.retroshades_main(meta).await;

        Ok(())
    }

    async fn hanlde_commitee_state_response(
        &mut self,
        state: &AggregateSignatureData<ChainStateResponseKind>,
    ) -> anyhow::Result<()> {
        let state_ok = self.verify_aggregated_signature(state);


        Ok(())
    }
}
