use std::sync::Arc;

use hash::{Blake2bHash, Hash};
use bls::bls12_381::{Signature, PublicKey, AggregatePublicKey};
use collections::bitset::BitSet;
use futures_cpupool::{CpuPool, CpuFuture};
use futures::{Future, future, future::FutureResult};

use crate::handel::IdentityRegistry;
use crate::handel::MultiSignature;


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    Ok,
    UnknownSigner { signer: usize },
    InvalidSignature,
    ThresholdNotReached { votes: usize, threshold: usize },
}


pub type VerifyFuture = CpuFuture<VerifyResult, ()>;


pub struct Verifier {
    threshold: usize,
    message_hash: Blake2bHash,
    identities: Arc<IdentityRegistry>,
    workers: CpuPool,
}


impl Verifier {
    pub fn new(threshold: usize, message_hash: Blake2bHash, identities: Arc<IdentityRegistry>, num_workers: Option<usize>) -> Self {
        let workers = if let Some(n) = num_workers {
            CpuPool::new(n)
        }
        else {
            CpuPool::new_num_cpus()
        };

        Self {
            threshold,
            message_hash,
            identities,
            workers,
        }
    }

    pub fn verify_individual(&self, signature: Signature, signer: usize) -> VerifyFuture {
        let message_hash = self.message_hash.clone();
        let identities = Arc::clone(&self.identities);

        self.workers.spawn_fn(move || {
            let result = if let Some(identity) = identities.get_by_id(signer) {
                if identity.public_key.verify_hash(message_hash, &signature) {
                    VerifyResult::Ok
                }
                else {
                    VerifyResult::InvalidSignature
                }
            }
            else {
                VerifyResult::UnknownSigner { signer }
            };
            future::ok::<VerifyResult, ()>(result)
        })
    }

    pub fn verify_multisig(&self, signature: MultiSignature) -> VerifyFuture {
        let identities = Arc::clone(&self.identities);
        let message_hash = self.message_hash.clone();
        let threshold = self.threshold;

        self.workers.spawn_fn(move || {
            let mut public_key = AggregatePublicKey::new();
            let mut votes = 0;

            for signer in signature.signers.iter() {
                if let Some(identity) = identities.get_by_id(signer) {
                    public_key.aggregate(&identity.public_key);
                    votes += identity.weight;
                }
                else {
                    return future::ok(VerifyResult::UnknownSigner { signer });
                }
            }

            let result = if votes < threshold {
                VerifyResult::ThresholdNotReached { votes, threshold }
            }
            else if public_key.verify_hash(message_hash, &signature.signature) {
                VerifyResult::Ok
            }
            else {
                VerifyResult::InvalidSignature
            };

            future::ok(result)
        })
    }
}
