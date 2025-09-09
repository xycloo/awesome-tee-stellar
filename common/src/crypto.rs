use anyhow::{Context, anyhow};
use blst::min_pk::{self as bls, AggregateSignature, Signature};

use crate::message::{NetworkingMessage, ToSigningHash};

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

fn verify_signature<M>(message: M, expected_signer: &[u8], signature: &[u8]) -> anyhow::Result<()>
where
    M: ToSigningHash,
{
    let msg = message
        .compute_hash()
        .context("compute signing hash for BLS")?;

    let pk = bls::PublicKey::from_bytes(expected_signer)
        .map_err(|_| anyhow::anyhow!("invalid BLS public key bytes"))?;
    let sig = bls::Signature::from_bytes(signature)
        .map_err(|_| anyhow::anyhow!("invalid BLS signature bytes"))?;

    let err = sig.verify(true, &msg, DST, &[], &pk, true);
    if err != blst::BLST_ERROR::BLST_SUCCESS {
        anyhow::bail!("BLS signature verification failed: {:?}", err);
    }
    Ok(())
}

impl NetworkingMessage {
    pub fn verify(&self) -> anyhow::Result<()> {
        verify_signature(self.inner(), &self.signer(), &self.signature())
    }
}

pub trait SigCombiner {
    /// Combine `current` (if any) with `incoming` and return the new aggregate.
    fn combine(current: Option<&[u8]>, incoming: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// aggregates signatures in G2.
#[derive(Clone, Copy, Default)]
pub struct BlstMinPkCombiner;

impl SigCombiner for BlstMinPkCombiner {
    fn combine(current: Option<&[u8]>, incoming: &[u8]) -> anyhow::Result<Vec<u8>> {
        let sig_in = Signature::from_bytes(incoming)
            .map_err(|e| anyhow!("invalid incoming signature bytes: {:?}", e))?;

        let agg = match current {
            None => AggregateSignature::from_signature(&sig_in),
            Some(cur_bytes) => {
                let sig_cur = Signature::from_bytes(cur_bytes)
                    .map_err(|e| anyhow!("invalid current aggregate bytes: {:?}", e))?;
                AggregateSignature::aggregate(&[&sig_cur, &sig_in], true)
                    .map_err(|e| anyhow!("failed to aggregate signatures: {:?}", e))?
            }
        };

        let agg_sig = agg.to_signature();

        Ok(agg_sig.to_bytes().to_vec())
    }
}
