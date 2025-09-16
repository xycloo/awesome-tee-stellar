use std::collections::HashMap;

use client::{BlockchainClient, CommitteeNode};
use common::message::{
    ChainEventKind, ChainStateRequestKind, ChainStateResponseKind, StellarLedgerEntry,
    StellarStateResponse,
};
use stellar_xdr::next::{LedgerEntry, Limits, ReadXdr, WriteXdr};
use tokio::{runtime::Builder, sync::mpsc, task::LocalSet};
use zephyr::snapshot::raw_endpoint::configurable_entry_and_ttl;

mod event;

pub struct StellarClient {
    pub core_endpoint: String,
    pub network: String,
}

impl StellarClient {
    pub fn new(core_endpoint: String, network: String) -> Self {
        Self { core_endpoint, network }
    }

    pub fn client_from_self(self, signing_key: &[u8; 32]) -> anyhow::Result<CommitteeNode<Self>> {
        let node = CommitteeNode::new(signing_key, self)?;
        Ok(node)
    }
}

impl BlockchainClient for StellarClient {
    fn spawn_chain_event_worker(&self) -> anyhow::Result<mpsc::Receiver<ChainEventKind>> {
        let (sender, receiver) = mpsc::channel(20);
        let network = self.network.clone();

        std::thread::spawn(move || {
            tracing::info!("running on own thread");
            let rt = Builder::new_multi_thread()
                .enable_all()
                .worker_threads(4)
                .build()
                .expect("build current_thread runtime");

            let local = LocalSet::new();

            tracing::info!("running on localset");
            rt.block_on(local.run_until(async move {
                if let Err(e) = event::run_stellar_core(sender, network).await {
                    tracing::error!(?e, "run_stellar_core exited");
                }
            }));
        });

        Ok(receiver)
    }

    fn retrieve_chain_state(
        &self,
        requested_state: common::message::ChainStateRequestKind,
    ) -> anyhow::Result<common::message::ChainStateResponseKind> {
        match requested_state {
            ChainStateRequestKind::ChainState(state_request) => {
                let mut response = HashMap::new();

                for key in state_request.inner() {
                    let entry = configurable_entry_and_ttl(
                        key.to_xdr(Limits::none()).unwrap(),
                        self.core_endpoint.clone(),
                    )?;
                    if let Some((entry, ttl)) = entry {
                        response.insert(
                            key,
                            StellarLedgerEntry::new(
                                LedgerEntry::from_xdr(entry, Limits::none())?,
                                ttl,
                            ),
                        );
                    }
                }

                Ok(ChainStateResponseKind::ChainState(
                    StellarStateResponse::new(response),
                ))
            }
        }
    }
}
