use std::sync::Arc;

use hash::Blake2bHash;
use bls::bls12_381::{Signature, AggregatePublicKey};
use futures_cpupool::{CpuPool, CpuFuture};
use futures::{future, Future};
use stopwatch::Stopwatch;

use crate::handel::IdentityRegistry;
use crate::handel::MultiSignature;
use futures::future::FutureResult;


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    Ok { votes: usize },
    UnknownSigner { signer: usize },
    InvalidSignature,
    ThresholdNotReached { votes: usize, threshold: usize },
}


pub trait Verifier {
    type Output: Future<Item=VerifyResult, Error=()>;

    fn verify_individual(&self, signature: Signature, signer: usize) -> Self::Output;
    fn verify_multisig(&self, signature: MultiSignature, check_threshold: bool) -> Self::Output;
}


pub struct ThreadPoolVerifier {
    threshold: usize,
    message_hash: Blake2bHash,
    identities: Arc<IdentityRegistry>,
    workers: CpuPool,
}


impl ThreadPoolVerifier {
    pub fn new(threshold: usize, message_hash: Blake2bHash, identities: Arc<IdentityRegistry>, num_workers: Option<usize>) -> Self {
        let workers = if let Some(n) = num_workers {
            CpuPool::new(n)
        } else {
            CpuPool::new_num_cpus()
        };

        Self {
            threshold,
            message_hash,
            identities,
            workers,
        }
    }
}

impl Verifier for ThreadPoolVerifier {
    type Output = CpuFuture<VerifyResult, ()>;

    fn verify_individual(&self, signature: Signature, signer: usize) -> Self::Output {
        let message_hash = self.message_hash.clone();
        let identities = Arc::clone(&self.identities);

        self.workers.spawn_fn(move || {
            let mut stopwatch = Stopwatch::start_new();

            let result = if let Some(identity) = identities.get_by_id(signer) {
                if identity.public_key.verify_hash(message_hash, &signature) {
                    VerifyResult::Ok { votes: 1 }
                }
                else {
                    VerifyResult::InvalidSignature
                }
            }
            else {
                VerifyResult::UnknownSigner { signer }
            };

            stopwatch.stop();
            info!("Took {} ms to verify individual signature", stopwatch.elapsed_ms());

            Ok(result)
        })
    }

    fn verify_multisig(&self, signature: MultiSignature, check_threshold: bool) -> Self::Output {
        let identities = Arc::clone(&self.identities);
        let message_hash = self.message_hash.clone();
        let threshold = self.threshold;

        self.workers.spawn_fn(move || {
            let mut stopwatch = Stopwatch::start_new();

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

            let result = if check_threshold && votes < threshold {
                VerifyResult::ThresholdNotReached { votes, threshold }
            }
            else if public_key.verify_hash(message_hash, &signature.signature) {
                VerifyResult::Ok { votes }
            }
            else {
                VerifyResult::InvalidSignature
            };

            stopwatch.stop();
            info!("Took {} ms to verify multi-signature", stopwatch.elapsed_ms());

            Ok(result).into()
        })
    }
}


pub struct DummyVerifier {
    threshold: usize,
    identities: Arc<IdentityRegistry>,
}

impl DummyVerifier {
    pub fn new(threshold: usize, identities: Arc<IdentityRegistry>) -> Self {
        Self {
            threshold,
            identities,
        }
    }
}

impl Verifier for DummyVerifier {
    type Output = FutureResult<VerifyResult, ()>;

    fn verify_individual(&self, signature: Signature, signer: usize) -> Self::Output {
        Ok(VerifyResult::Ok { votes: 1 }).into()
    }

    fn verify_multisig(&self, signature: MultiSignature, check_threshold: bool) -> Self::Output {
        let mut votes = 0;

        for signer in signature.signers.iter() {
            if let Some(identity) = self.identities.get_by_id(signer) {
                votes += identity.weight;
            }
            else {
                return future::ok(VerifyResult::UnknownSigner { signer });
            }
        }

        let result = if check_threshold && votes < self.threshold {
            VerifyResult::ThresholdNotReached {
                votes: signature.len(),
                threshold: self.threshold
            }
        }
        else {
            VerifyResult::Ok { votes }
        };

        Ok(result).into()
    }
}

/*impl<V: Verifier + ?Sized> Verifier for Box<V> {
    type Output = <V as Verifier>::Output;

    fn verify_individual(&self, signature: Signature, signer: usize) -> Self::Output {
        (**self).verify_individual(signature, signer)
    }

    fn verify_multisig(&self, signature: MultiSignature, check_threshold: bool) -> Self::Output {
        (**self).verify_multisig(signature, check_threshold)
    }
}*/
