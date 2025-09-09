use std::collections::HashMap;

use client::{BlockchainClient, CommitteeNode};
use common::message::{
    ChainEventKind, ChainStateRequestKind, ChainStateResponseKind, StellarLedgerEntry,
    StellarStateResponse,
};
use secp256k1::SecretKey;
use stellar_xdr::next::{LedgerEntry, Limits, ReadXdr, WriteXdr};
use tokio::sync::mpsc;
use zephyr::snapshot::raw_endpoint::configurable_entry_and_ttl;

mod event;

pub struct StellarClient {
    pub core_endpoint: String,
}

impl StellarClient {
    pub fn new(core_endpoint: String) -> Self {
        Self { core_endpoint }
    }

    pub fn client_from_self(self, signing_key: SecretKey) -> CommitteeNode<Self> {
        CommitteeNode::new(signing_key, self)
    }
}

impl BlockchainClient for StellarClient {
    fn spawn_chain_event_worker() -> anyhow::Result<mpsc::Receiver<ChainEventKind>> {
        {
            let (sender, receiver) = mpsc::channel(20);
            tokio::spawn(async move { event::run_stellar_core(sender).await });

            Ok(receiver)
        }
    }

    fn retrieve_chain_state(
        &self,
        requested_state: common::message::ChainStateRequestKind,
    ) -> anyhow::Result<common::message::ChainStateResponseKind> {
        match requested_state {
            ChainStateRequestKind::ChainState(state_request) => {
                let mut response = HashMap::new();

                for key in state_request.inner() {
                    let entry = configurable_entry_and_ttl(key, self.core_endpoint)?;
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
