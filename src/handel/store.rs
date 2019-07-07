use std::sync::Arc;

use bls::bls12_381::Signature;
use collections::bitset::BitSet;

use crate::handel::MultiSignature;
use crate::handel::BinomialPartitioner;
use std::collections::BTreeMap;


pub trait SignatureStore {
    fn evaluate_individual(&self, individual: &Signature, level: usize, peer_id: usize) -> usize;
    fn evaluate_multisig(&self, multisig: &MultiSignature, level: usize, votes: usize) -> usize;

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
        for _ in 0..partitioner.num_levels {
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

    fn check_merge(&self, multisig: &MultiSignature, level: usize) -> Option<MultiSignature> {
        if let Some(best_multisig) = self.multisig_best.get(&level) {
            // try to combine
            let mut multisig = multisig.clone();

            // we can ignore the error, if it's not possible to merge we continue
            multisig.add_multisig(best_multisig)
                .unwrap_or_else(|e| debug!("check_merge: combining multisigs failed: {}", e));

            let individual_verified = self.individual_verified.get(level)
                .unwrap_or_else(|| panic!("Individual verified signatures BitSet is missing for level {}", level));

            // the bits set here are verified individual signatures that can be added to `multisig`
            let complements = &(&multisig.signers & individual_verified) ^ individual_verified;

            // check that if we combine we get a better signature
            if complements.len() + multisig.len() <= best_multisig.len() {
                // doesn't get better
                None
            }
            else {
                // put in the individual signatures
                for id in complements.iter() {
                    // get individual signature
                    // TODO: Why do we need to store individual signatures per level?
                    let individual = self.individual_signatures.get(level)
                        .unwrap_or_else(|| panic!("Individual signatures missing for level {}", level))
                        .get(&id).unwrap_or_else(|| panic!("Individual signature with ID {} missing for level {}", id, level));

                    // merge individual signature into multisig
                    multisig.add_individual(individual, id)
                        .unwrap_or_else(|e| panic!("Individual signature form id={} can't be added to multisig: {}", id, e));
                }

                Some(multisig)
            }
        }
        else {
            Some(multisig.clone())
        }
    }
}


impl SignatureStore for ReplaceStore {
    fn evaluate_individual(&self, individual: &Signature, level: usize, peer_id: usize) -> usize {
        if self.individual_signatures.get(level)
            .unwrap_or_else(|| panic!("No individual signatures for level {}", level))
            .get(&peer_id).is_some() {
            //debug!("Individual signature already known");
            0
        }
        else {
            self.evaluate_multisig(&MultiSignature::from_individual(individual, peer_id), level, 1)
        }
    }

    fn evaluate_multisig(&self, multisig: &MultiSignature, level: usize, votes: usize) -> usize {
        // TODO: Signatures may have different weights and we could use that for scoring

        let to_receive = self.partitioner.size(level);
        let best_signature = self.multisig_best.get(&level);

        if let Some(best_signature) = best_signature {
            /*debug!("This is node {}", self.partitioner.node_id);
            debug!("level = {}", level);
            debug!("multisig = {:#?}", multisig);
            debug!("best_signature = {:#?}", best_signature);*/

            // check if the best signature for that level is already complete
            if to_receive == best_signature.len() {
                //debug!("Best signature already complete");
                return 0;
            }

            // check if the best signature is better than the new one
            if best_signature.signers.is_superset(&multisig.signers) {
                //debug!("Best signature is better");
                return 0;
            }
        }

        let with_individuals = &multisig.signers
            | self.individual_verified.get(level)
            .unwrap_or_else(|| panic!("Missing level {}", level));

        let (new_total, added_sigs, combined_sigs) = if let Some(best_signature) = best_signature {
            if multisig.signers.intersection_size(&best_signature.signers) > 0 {
                // can't merge
                let new_total = with_individuals.len();
                (new_total, new_total.saturating_sub(best_signature.len()), new_total - multisig.len())
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

        //debug!("new_total={}, added_sigs={}, combined_sigs={}", new_total, added_sigs, combined_sigs);

        if added_sigs == 0 {
            // XXX return 1 for an individual signature
            if multisig.len() == 1 { 1 } else { 0 }
        }
        else if new_total == to_receive {
            1000000 - level * 10 - combined_sigs
        }
        else {
            100000 - level * 100 + added_sigs * 10 - combined_sigs
        }
    }

    fn put_individual(&mut self, individual: Signature, level: usize, peer_id: usize) {
        //info!("Putting individual signature into store: level={}, id={}", level, peer_id);

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
        //info!("Putting multi-signature into store: level={}, ids={}", level, multisig.signers);

        if let Some(best_multisig) = self.check_merge(&multisig, level) {
            //debug!("Changing best multisig for level {}: signers={}", level, multisig.signers);
            self.multisig_best.insert(level, best_multisig);
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
        for (&i, signature) in self.multisig_best.range(0 ..= level) {
            if i > signatures.len()  {
                //warn!("MultiSignature missing for level {} to {}", signatures.len(), i - 1);
                return None;
            }
            signatures.push(signature)
        }

        // ???
        if level < self.partitioner.num_levels - 1 {
            level += 1;
        }

        //debug!("Combining signatures for level {}: {:?}", level, signatures);
        self.partitioner.combine(signatures, level)
    }
}