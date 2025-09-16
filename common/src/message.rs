use std::collections::HashMap;
//use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use stellar_xdr::next::{LedgerCloseMeta, LedgerEntry, LedgerKey, Limits, WriteXdr};

use crate::{crypto::DST, networking::Reference};

pub trait ToSigningHash {
    fn compute_hash(&self) -> anyhow::Result<[u8; 32]>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StellarLedgerClose {
    pub meta: Vec<u8>,
}

impl StellarLedgerClose {
    pub fn new(meta: LedgerCloseMeta) -> Self {
        Self { meta: meta.to_xdr(Limits::none()).unwrap() }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StellarLedgerEntry {
    pub entry: LedgerEntry,
    pub ttl: Option<u32>,
}

impl StellarLedgerEntry {
    pub fn new(entry: LedgerEntry, ttl: Option<u32>) -> Self {
        Self { entry, ttl }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StellarStateResponse(HashMap<LedgerKey, StellarLedgerEntry>);

impl StellarStateResponse {
    pub fn new(entries: HashMap<LedgerKey, StellarLedgerEntry>) -> Self {
        Self(entries)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StellarStateRequest(Vec<LedgerKey>);

impl StellarStateRequest {
    pub fn inner(&self) -> Vec<LedgerKey> {
        self.0.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ChainEventKind {
    LedgerClose(StellarLedgerClose),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainStateRequest {
    /// used by the overlay to know to which executor connection to route the payload,
    pub reference: Reference,
    pub kind: ChainStateRequestKind,
}

impl ChainStateRequest {
    pub fn new(reference: Reference, kind: ChainStateRequestKind) -> Self {
        Self { reference, kind }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ChainStateRequestKind {
    ChainState(StellarStateRequest),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainStateResponse {
    /// used by the overlay to know to which executor connection to route the payload,
    pub reference: Reference,
    pub kind: ChainStateResponseKind,
}

impl ChainStateResponse {
    pub fn new(reference: Reference, kind: ChainStateResponseKind) -> Self {
        Self { reference, kind }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ChainStateResponseKind {
    ChainState(StellarStateResponse),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AggregateSignatureData<T> {
    pub inner: T,
    pub signers: Vec<Vec<u8>>,
    pub aggregated_signature: Vec<u8>,
}

impl<T> AggregateSignatureData<T> {
    pub fn new(inner: T, signers: Vec<Vec<u8>>, aggregated_signature: Vec<u8>) -> Self {
        Self {
            inner,
            signers,
            aggregated_signature,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MessageKind {
    ChainEvent(ChainEventKind),
    CollectorChainStateRequest(ChainStateRequest),
    CollectorChainStateResponse(ChainStateResponse),
    ExecutorChainStateRequest(ChainStateRequestKind),
    ExecutorChainStateResponse(AggregateSignatureData<ChainStateResponseKind>),
    ExecutorChainEvent(AggregateSignatureData<ChainEventKind>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkingMessage {
    kind: MessageKind,
    pubkey: Vec<u8>,
    signature: Vec<u8>,
}

impl NetworkingMessage {
    pub fn inner(&self) -> MessageKind {
        self.kind.clone()
    }

    pub fn set_inner(&mut self, new: MessageKind) {
        self.kind = new;
    }

    pub fn signer(&self) -> Vec<u8> {
        self.pubkey.clone()
    }

    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn new(message: MessageKind, signing_key: blst::min_pk::SecretKey) -> anyhow::Result<Self> {
        let hash = message.compute_hash()?;

        let signature = signing_key.sign(&hash, DST, &[]);
        let signature_bytes = signature.to_bytes().to_vec();

        let pubkey_bytes = signing_key.sk_to_pk().to_bytes().to_vec();

        Ok(Self {
            kind: message,
            signature: signature_bytes,
            pubkey: pubkey_bytes,
        })
    }
}

impl ToSigningHash for MessageKind {
    fn compute_hash(&self) -> anyhow::Result<[u8; 32]> {
        let payload = match self {
            MessageKind::ChainEvent(r) => bincode::serialize(&r)?,
            MessageKind::CollectorChainStateRequest(r) => bincode::serialize(&r.kind)?,
            MessageKind::CollectorChainStateResponse(r) => bincode::serialize(&r.kind)?,
            MessageKind::ExecutorChainStateRequest(r) => bincode::serialize(&r)?,
            MessageKind::ExecutorChainStateResponse(r) => bincode::serialize(&r.inner)?,
            MessageKind::ExecutorChainEvent(r) => bincode::serialize(&r.inner)?,
        };

        let hash: [u8; 32] = sha2::Sha256::digest(&payload).try_into()?;

        Ok(hash)
    }
}

impl ToSigningHash for ChainEventKind {
    fn compute_hash(&self) -> anyhow::Result<[u8; 32]> {
        let payload = bincode::serialize(&self)?;
        let hash: [u8; 32] = sha2::Sha256::digest(&payload).try_into()?;

        Ok(hash)
    }
}

impl ToSigningHash for ChainStateResponseKind {
    fn compute_hash(&self) -> anyhow::Result<[u8; 32]> {
        let payload = bincode::serialize(&self)?;
        let hash: [u8; 32] = sha2::Sha256::digest(&payload).try_into()?;

        Ok(hash)
    }
}
