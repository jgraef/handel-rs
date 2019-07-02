use std::sync::Arc;

use bls::bls12_381::Signature;
use collections::bitset::BitSet;

use crate::handel::MultiSignature;
use crate::handel::BinomialPartitioner;
use std::collections::BTreeMap;


pub trait SignatureStore {
    fn evaluate_individual(&self, individual: &Signature, level: usize, peer_id: usize) -> usize;
    fn evaluate_multisig(&self, multisig: &MultiSignature, level: usize) -> usize;

    fn put_individual(&mut self, individual: Signature, level: usize, peer_id: usize);
    fn put_multisig(&mut self, multisig: MultiSignature, level: usize);

    fn best(&self, level: usize) -> Option<&MultiSignature>;
    fn combined(&self, level: usize) -> Option<MultiSignature>;
}


#[derive(Clone, Debug)]
pub struct ReplaceStore {
    partitioner: Arc<BinomialPartitioner>,

    best_level: usize,

    /// BitSet that contains the IDs of all individual signatures we already received
    individual_received: BitSet,

    /// BitSets for all the individual signatures that we already verified
    /// level -> bitset
    individual_verified: Vec<BitSet>,

    /// All individual signatures
    /// level -> ID -> Signature
    individual_signatures: Vec<BTreeMap<usize, Signature>>,

    /// The best MultiSignature at each level
    multisig_best: BTreeMap<usize, MultiSignature>,
}


impl ReplaceStore {
    pub fn new(partitioner: Arc<BinomialPartitioner>) -> ReplaceStore {
        let n = partitioner.max_id + 1;

        let mut individual_verified = Vec::with_capacity(partitioner.num_levels);
        let mut individual_signatures = Vec::with_capacity(partitioner.num_levels);
        for i in 0..partitioner.num_levels {
            individual_verified.push(BitSet::new());
            individual_signatures.push(BTreeMap::new());
        }

        ReplaceStore {
            partitioner,
            best_level: 0,
            individual_received: BitSet::with_capacity(n),
            individual_verified,
            individual_signatures,
            multisig_best: BTreeMap::new(),
        }
    }

    fn check_merge(&self, multisig: &MultiSignature, level: usize) -> (MultiSignature, bool) {
        unimplemented!()
    }
}


impl SignatureStore for ReplaceStore {
    fn evaluate_individual(&self, individual: &Signature, level: usize, peer_id: usize) -> usize {
        unimplemented!()
    }

    fn evaluate_multisig(&self, multisig: &MultiSignature, level: usize) -> usize {
        // TODO: Signatures may have different weights and we could use that for scoring

        let to_receive = self.partitioner.size(level);
        let best_signature = self.multisig_best.get(&level);

        if let Some(best_signature) = best_signature {
            // check if the best signature for that level is already complete
            if to_receive == best_signature.len() {
                return 0;
            }

            // check if the best signature is better than the new one
            if best_signature.signers.is_superset(&multisig.signers) {
                return 0;
            }
        }

        // TODO: For an individual signature we check if we have a verified individual signature for that level


        let with_individuals = &multisig.signers
            | self.individual_verified.get(level)
            .unwrap_or_else(|| panic!("Missing level {}", level));

        let (new_total, added_sigs, combined_sigs) = if let Some(best_signature) = best_signature {
            if multisig.signers.intersection_size(&best_signature.signers) > 0 {
                // can't merge
                let new_total = with_individuals.len();
                (new_total, new_total - best_signature.len(), new_total - multisig.len())
            }
            else {
                let final_sig = &with_individuals | &best_signature.signers;
                let new_total = final_sig.len();
                let combined_sigs = (final_sig ^ (&best_signature.signers | &multisig.signers)).len();
                (new_total, new_total - best_signature.len(), combined_sigs)
            }
        }
        else {
            // best is the new signature with the individual signatures
            let new_total = with_individuals.len();
            (new_total, new_total, new_total - multisig.len())
        };

        if added_sigs == 0 {
            // TODO: return 1 for an individual signature
            0
        }
        else if new_total == to_receive {
            1000000 - level * 10 - combined_sigs
        }
        else {
            100000 - level * 100 + added_sigs * 10 - combined_sigs
        }
    }

    fn put_individual(&mut self, individual: Signature, level: usize, peer_id: usize) {
        let multisig = MultiSignature::from_individual(&individual, peer_id);

        self.individual_verified.get_mut(level)
            .unwrap_or_else(|| panic!("Missing level {}", level))
            .insert(peer_id);

        self.individual_signatures.get_mut(level)
            .unwrap_or_else(|| panic!("Missing level {}", level))
            .insert(peer_id, individual);

        self.put_multisig(multisig, level)
    }

    fn put_multisig(&mut self, multisig: MultiSignature, level: usize) {
        let (best_signature, store) = self.check_merge(&multisig, level);
        if store {
            self.multisig_best.insert(level, best_signature);
            if level > self.best_level {
                self.best_level = level;
            }
        }
    }

    fn best(&self, level: usize) -> Option<&MultiSignature> {
        self.multisig_best.get(&level)
    }

    fn combined(&self, mut level: usize) -> Option<MultiSignature> {
        let mut signatures = Vec::new();
        for (i, signature) in self.multisig_best.range(0 ..= level) {
            if *i + 1 > signatures.len()  {
                warn!("MultiSignature missing for level {}", i);
                return None;
            }
            signatures.push(signature)
        }

        // ???
        if level < self.partitioner.num_levels - 1 {
            level += 1;
        }

        self.partitioner.combine(signatures, level)
    }
}