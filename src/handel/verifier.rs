use std::sync::Arc;

use hash::{Blake2bHash, Hash};
use bls::bls12_381::{Signature, PublicKey, AggregatePublicKey};
use collections::bitset::BitSet;

use crate::handel::IdentityRegistry;
use crate::handel::MultiSignature;


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    Ok,
    UnknownSigner { signer: usize },
    InvalidSignature,
    ThresholdNotReached { votes: usize, threshold: usize },
}


pub struct Verifier {
    threshold: usize,
    message_hash: Blake2bHash,
    identities: Arc<IdentityRegistry>,
}


impl Verifier {
    pub fn new(threshold: usize, message_hash: Blake2bHash, identities: Arc<IdentityRegistry>) -> Self {
        Self {
            threshold,
            message_hash,
            identities,
        }
    }

    pub fn verify_individual(&self, signature: &Signature, signer: usize) -> VerifyResult {
        if let Some(identity) = self.identities.get_by_id(signer) {
            if identity.public_key.verify_hash(self.message_hash.clone(), signature) {
                VerifyResult::Ok
            }
            else {
                VerifyResult::InvalidSignature
            }
        }
        else {
            VerifyResult::UnknownSigner { signer }
        }
    }

    pub fn verify_multisig(&self, signature: &MultiSignature) -> VerifyResult {
        let mut public_key = AggregatePublicKey::new();
        let mut votes = 0;

        for signer in signature.signers.iter() {
            if let Some(identity) = self.identities.get_by_id(signer) {
                public_key.aggregate(&identity.public_key);
                votes += identity.weight;
            }
            else {
                return VerifyResult::UnknownSigner { signer };
            }
        }

        if votes < self.threshold {
            VerifyResult::ThresholdNotReached { votes, threshold: self.threshold }
        }
        else if public_key.verify_hash(self.message_hash.clone(), &signature.signature) {
            VerifyResult::Ok
        }
        else {
            VerifyResult::InvalidSignature
        }
    }
}
