use std::sync::Arc;
use std::net::SocketAddr;
use std::io::Error as IoError;

use parking_lot::RwLock;
use failure::{Fail, Error};
use futures::{Future, future, Join};
use futures_cpupool::CpuFuture;

use beserial::Serialize;

use crate::handel::{
    IdentityRegistry, Message, Handler, Config, BinomialPartitioner, Level,
    SignatureProcessing, ProcessingError
};
use futures::future::{FutureResult, Either};
use std::convert::TryInto;


#[derive(Debug, Fail)]
pub enum AgentError {
    #[fail(display = "Processing error: {}", _0)]
    Processing(#[cause] ProcessingError),
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

impl From<ProcessingError> for AgentError {
    fn from(e: ProcessingError) -> Self {
        AgentError::Processing(e)
    }
}


pub struct HandelState {
    done: bool,
}

pub struct HandelAgent {
    state: RwLock<HandelState>,
    config: Config,
    identities: Arc<IdentityRegistry>,
    partitioner: BinomialPartitioner,
    levels: Vec<Level>,
    processing: SignatureProcessing,
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
        let partitioner = BinomialPartitioner::new(config.node_identity.id, max_id);
        let levels = Level::create_levels(&config, &partitioner);

        HandelAgent {
            state: RwLock::new(HandelState {
                done: false,
            }),
            config,
            identities,
            partitioner,
            levels,
            processing: SignatureProcessing::new(),
        }
    }
}

pub type MessageHandlerFuture = Join<CpuFuture<(), ProcessingError>, Either<CpuFuture<(), ProcessingError>, FutureResult<(), ProcessingError>>>;

impl Handler for Arc<HandelAgent> {
    type Result = MessageHandlerFuture;
    //type Error = AgentError;

    fn on_message(&self, message: Message, sender_address: SocketAddr) -> Result<MessageHandlerFuture, Error> {
        let guard = self.state.read();

        if !guard.done {
            // deconstruct message
            let Message {
                origin,
                level,
                multisig,
                individual,
            } = message;

            // convert origin and level to usize
            let origin: usize = origin.try_into()?;
            let level: usize = level.try_into()?;

            info!("Received message from address={} id={} for level={}", sender_address, origin, level);

            // send multisig and individual to processor
            Ok(self.processing.process_multisig(multisig, origin, level)
                .join(match individual {
                    Some(signature) => {
                        Either::A(self.processing.process_individual(signature, origin, level))
                    },
                    None => Either::B(future::ok::<(), ProcessingError>(())),
                }))
        }
        else {
            // TODO: is that the correct error or should we fail at all?
            Err(AgentError::Done)?
        }
    }
}
