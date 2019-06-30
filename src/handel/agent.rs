use std::sync::Arc;
use std::net::SocketAddr;
use std::io::Error as IoError;
use std::io::ErrorKind;

use parking_lot::RwLock;
use failure::{Fail, Error};
use futures::{Future, future, Join};
use futures_cpupool::CpuFuture;

use beserial::Serialize;
use bls::bls12_381::Signature;

use crate::handel::{
    IdentityRegistry, Message, Handler, Config, BinomialPartitioner, Level, MultiSignature,
};
use futures::future::{FutureResult, Either};
use std::convert::TryInto;


#[derive(Debug, Fail)]
pub enum AgentError {
    #[fail(display = "IO error: {}", _0)]
    Io(#[cause] IoError),
    #[fail(display = "Aggregation finished")]
    Done,
}

impl From<IoError> for AgentError {
    fn from(e: IoError) -> Self {
        AgentError::Io(e)
    }
}


pub struct HandelState {
    done: bool,
}

pub struct HandelAgent {
    state: RwLock<HandelState>,
    config: Config,
    identities: Arc<IdentityRegistry>,
    partitioner: Arc<BinomialPartitioner>,
    levels: Vec<Level>,

}


impl HandelAgent {
    pub fn new(config: Config, identities: IdentityRegistry) -> HandelAgent {
        info!("New Handel Agent:");
        info!(" - ID: {}", config.node_identity.id);
        info!(" - Address: {}", config.node_identity.address);
        info!(" - Public Key: {}", hex::encode(config.node_identity.public_key.serialize_to_vec()));

        info!("Identities:");
        let mut max_id = 0;
        for identity in identities.all().iter() {
            let pk_hex = &hex::encode(identity.public_key.serialize_to_vec())[0..8];
            info!(" {:>5}: {} - {}", identity.id, identity.address, pk_hex);
            max_id = max_id.max(identity.id);
        }

        let identities = Arc::new(identities);
        let partitioner = Arc::new(BinomialPartitioner::new(config.node_identity.id, max_id));
        let levels = Level::create_levels(&config, Arc::clone(&partitioner));

        HandelAgent {
            state: RwLock::new(HandelState {
                done: false,
            }),
            config,
            identities,
            partitioner,
            levels,
        }
    }

    fn process_multisig(&self, multisig: MultiSignature, origin: usize, level: usize) {

    }

    fn process_individual(&self, individual: Signature, origin: usize, level: usize) {

    }
}


impl Handler for Arc<HandelAgent> {
    type Result = Result<(), IoError>;

    fn on_message(&self, message: Message, sender_address: SocketAddr) -> Self::Result {
        let guard = self.state.read();

        if !guard.done {
            // deconstruct message
            let Message {
                origin,
                level,
                multisig,
                individual,
            } = message;

            info!("Received message from address={} id={} for level={}", sender_address, origin, level);

            self.process_multisig(multisig, origin as usize, level as usize);

            if let Some(sig) = individual {
                self.process_individual(sig, origin as usize, level as usize);
            }

            Ok(())
        }
        else {
            // TODO: is that the correct error or should we fail at all?
            Err(IoError::from(ErrorKind::ConnectionReset))
        }
    }
}
