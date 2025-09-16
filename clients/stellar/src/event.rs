
use common::message::{ChainEventKind, StellarLedgerClose};
use ingest::{CaptiveCore, IngestionConfig, SupportedNetwork};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

const PUBNET: &str = "Public Global Stellar Network ; September 2015";

#[derive(Deserialize, Serialize, Clone)]
pub struct StellarCoreConfig {
    pub network: String,
}

pub(crate) async fn run_stellar_core(sender: mpsc::Sender<ChainEventKind>, network: String) -> anyhow::Result<()> {    
    let network = if network == PUBNET {
        SupportedNetwork::Pubnet
    } else {
        SupportedNetwork::Testnet
    };

    tracing::info!(target: "info", "Booting up service for network {:?}", network);

    let ingestion_config = IngestionConfig {
        executable_path: "/usr/local/bin/stellar-core".to_string(),
        context_path: Default::default(),
        network,
        bounded_buffer_size: None,
        staggered: None,
    };

    let mut captive = CaptiveCore::new(ingestion_config);
    tracing::info!(target: "info", "Starting to receive streamed ledger metas from stellar core");
    let mut rv = captive
        .async_start_online_no_range()
        .await
        .expect("failed to start ingesting");
    tracing::info!(target: "info", "Started online streaming.");

    loop {
        let result = rv.recv().await;
        if let Some(result) = result {
            tracing::info!("Got new meta object.");
            let ledger = if let Some(ledger_wrapper) = result.ledger_close_meta {
                ledger_wrapper.ledger_close_meta
            } else {
                tracing::error!("Core stopped catching up");
                captive.close_runner_process().unwrap();
                std::process::exit(0);
            };

            // this is unrecoverable, means the node wrapper dropped
            sender
                .send(ChainEventKind::LedgerClose(StellarLedgerClose::new(ledger)))
                .await
                .unwrap();
        } else {
            tracing::error!("couldn't receive on receiver",);
        }
    }
    
}
