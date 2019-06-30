use bls::bls12_381::Signature;

use futures_cpupool::{CpuPool, CpuFuture};
use futures::future;
use failure::Fail;

use crate::handel::MultiSignature;



#[derive(Debug, Fail)]
pub enum ProcessingError {
    #[fail(display = "Test")]
    Dummy,
}

pub struct SignatureProcessing {
    workers: CpuPool,
}


impl SignatureProcessing {
    pub fn new() -> SignatureProcessing {
        SignatureProcessing {
            workers: CpuPool::new_num_cpus(),
        }
    }

    pub fn process_multisig(&self, multisig: MultiSignature, origin: usize, level: usize) -> CpuFuture<(), ProcessingError> {
        self.workers.spawn_fn(move || {
            debug!("Processing: {:?}", multisig);

            // TODO

            future::ok::<(), ProcessingError>(())
        })
    }

    pub fn process_individual(&self, individual: Signature, origin: usize, level: usize) -> CpuFuture<(), ProcessingError> {
        self.workers.spawn_fn(move || {
            debug!("Processing: {:?}", individual);

            // TODO

            future::ok::<(), ProcessingError>(())
        })
    }
}

