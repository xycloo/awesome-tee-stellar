use std::{collections::HashSet, marker::PhantomData};

use common::crypto::SigCombiner;

/// Tracks threshold progress + aggregated signature.
pub struct ThresholdRules<C: SigCombiner> {
    required: usize,
    unique_signers: HashSet<Vec<u8>>,
    aggregated_sig: Option<Vec<u8>>,
    combiner: PhantomData<C>,
}

impl<C: SigCombiner> ThresholdRules<C> {
    pub fn new(required: usize) -> Self {
        Self {
            required,
            unique_signers: HashSet::new(),
            aggregated_sig: None,
            combiner: PhantomData {},
        }
    }

    pub fn add_signature(
        &mut self,
        signer_id: Vec<u8>,
        signature: &[u8],
    ) -> anyhow::Result<(usize, usize, bool)> {
        if self.unique_signers.insert(signer_id) {
            self.aggregated_sig = Some(C::combine(self.aggregated_sig.as_deref(), signature)?);
        }
        let count = self.unique_signers.len();
        Ok((count, self.required, count >= self.required))
    }

    pub fn participating_signers(&self) -> Vec<Vec<u8>> {
        self.unique_signers.clone().into_iter().collect()
    }

    pub fn reached(&self) -> bool {
        self.unique_signers.len() >= self.required
    }

    pub fn count(&self) -> usize {
        self.unique_signers.len()
    }

    pub fn required(&self) -> usize {
        self.required
    }

    pub fn aggregated(&self) -> Option<&[u8]> {
        self.aggregated_sig.as_deref()
    }
}
