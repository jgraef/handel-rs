use std::sync::Arc;
use std::net::SocketAddr;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::convert::TryInto;

use parking_lot::RwLock;
use failure::{Fail, Error};
use futures::{Future, future, Join, Stream, IntoFuture};
use futures::future::{FutureResult, Either, ok};
use futures_cpupool::CpuFuture;
use tokio::timer::Interval;

use beserial::Serialize;
use bls::bls12_381::Signature;

use crate::handel::{
    IdentityRegistry, Message, Config, BinomialPartitioner, Level, MultiSignature, Handler,
    SignatureStore, ReplaceStore, Verifier, VerifyResult, Identity, HandelSink, HandelStream,
    LinearTimeout
};
use futures::sync::mpsc::SendError;
use futures::executor::Spawn;
use crate::handel::timeout::TimeoutStrategy;


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


enum Todo {
    Individual { signature: Signature, level: usize, origin: usize },
    Multi { signature: MultiSignature, level: usize }
}

impl Todo {
    pub fn evaluate(&self, store: &ReplaceStore) -> usize {
        match self {
            Todo::Multi { signature, level } => store.evaluate_multisig(signature, *level),
            Todo::Individual { signature, level, origin } => store.evaluate_individual(signature, *level, *origin)
        }
    }

    pub fn put(self, store: &mut ReplaceStore) {
        match self {
            Todo::Individual { signature, level, origin } => {
                store.put_individual(signature, level, origin)
            }
            Todo::Multi { signature, level } => {
                store.put_multisig(signature, level)
            }
        }
    }
}



pub struct HandelState {
    pub done: bool,
    todos: Vec<Todo>,
    pub store: ReplaceStore,
}

impl HandelState {
    fn get_best_todo(&mut self) -> Option<(Todo, usize)> {
        let mut best_i = 0;
        let mut best_score = self.todos.first()?.evaluate(&self.store);

        for (i, todo) in self.todos.iter().enumerate().skip(1) {
            let score = todo.evaluate(&self.store);
            if score > best_score {
                best_i = i;
                best_score = score;
            }
        }
        if best_score > 0 {
            let best_todo = self.todos.swap_remove(best_i);
            Some((best_todo, best_score))
        }
        else {
            None
        }
    }
}


pub struct HandelAgent {
    /// State that is modified from multiple threads
    state: RwLock<HandelState>,

    /// Handel configuration
    config: Config,

    /// All known identities
    identities: Arc<IdentityRegistry>,

    /// Partitions IDs into levels
    partitioner: Arc<BinomialPartitioner>,

    /// Multi-threaded signature verification
    verifier: Verifier,

    /// Sink to send messages to other peers
    sink: HandelSink,

    /// Level timeouts
    timeouts: LinearTimeout,

    /// Our individual signature
    individual: Signature,

    /// Levels
    levels: Vec<Level>,
}


impl HandelAgent {
    pub fn new(config: Config, identities: IdentityRegistry, sink: HandelSink) -> HandelAgent {
        info!("New Handel Agent:");
        info!(" - ID: {}", config.node_identity.id);
        info!(" - Address: {}", config.node_identity.address);
        info!(" - Public Key: {}", hex::encode(config.node_identity.public_key.serialize_to_vec()));

        info!("Identities (n={}):", identities.len());
        let mut max_id = 0;
        for identity in identities.all().iter() {
            let pk_hex = &hex::encode(identity.public_key.serialize_to_vec())[0..8];
            info!(" {:>5}: address={}, pubkey={}, weight={}", identity.id, identity.address, pk_hex, identity.weight);
            max_id = max_id.max(identity.id);
        }

        // initialize EVERYTHING!
        let identities = Arc::new(identities);
        let partitioner = Arc::new(BinomialPartitioner::new(config.node_identity.id, max_id));
        let levels = Level::create_levels(&config, Arc::clone(&partitioner));
        let mut store = ReplaceStore::new(Arc::clone(&partitioner));
        let verifier = Verifier::new(config.threshold, config.message_hash.clone(), Arc::clone(&identities), None);
        let individual = config.individual_signature();

        // put our own individual signature into store
        store.put_individual(individual.clone(), 0, config.node_identity.id);
        store.put_multisig(MultiSignature::from_individual(&individual, config.node_identity.id), 0);
        debug!("{:#?}", store);

        /*debug!("Levels (n={}):", levels.len());
        for level in levels.iter() {
            debug!("  Level {}: {:#?}", level.id, level);
        }*/

        HandelAgent {
            state: RwLock::new(HandelState {
                done: false,
                todos: Vec::new(),
                store,
            }),
            config,
            identities,
            partitioner,
            verifier,
            sink,
            timeouts: LinearTimeout::default(),
            individual,
            levels,
        }
    }

    fn send_to(&self, to: Vec<usize>, multisig: MultiSignature, individual: Option<Signature>, level: usize) -> Result<(), SendError<(Message, SocketAddr)>> {
        let message = Message {
            origin: self.config.node_identity.id as u16,
            level: level as u8,
            multisig,
            individual,
        };

        debug!("Sending to {:?}: {:?}", to, message);

        for id in to {
            if let Some(identity) = self.identities.get_by_id(id) {
                self.sink.unbounded_send((message.clone(), identity.address.clone()))
                    .map_err(|e| {
                        error!("Send failed: {}", e);
                        e
                    })?;
            }
            else {
                error!("Unknown identity: id={}", id);
            }
        }

        Ok(())
    }

    fn on_timeout(&self, level: usize) {

    }

    /// Periodic update:
    ///  - check if timeout for level is reached. TODO: This is done with `on_timeout`
    ///  - send a new packet ???
    fn on_update(&self) {
        let mut state = self.state.write();

        // NOTE: Skip level 0
        for level in self.levels.iter().skip(1) {
            debug!("send update for level {}", level.id);
            // send update
            if let Some(multisig) = state.store.combined(level.id - 1) {
                let peer_ids = level.select_next_peers(self.config.update_count);

                let individual = if level.receive_completed { None } else { Some(self.individual.clone()) };

                // TODO: This can fail
                self.send_to(peer_ids, multisig.clone(), individual, level.id);
            }
        }
    }
}


pub type AgentFuture = Box<dyn Future<Item=(), Error=()> + Send>;

pub trait AgentProcessor {
    fn spawn(&self) -> AgentFuture;
}

impl AgentProcessor for Arc<HandelAgent> {
    fn spawn(&self) -> AgentFuture {
        let agent = Arc::clone(self);

        Box::new(future::lazy(move || {
            let timeouts = {
                let timeouts = agent.timeouts.timeouts(agent.levels.len());
                let agent = Arc::clone(&agent);
                tokio::spawn(timeouts.for_each(move |level| {
                    //debug!("Timeout for level {}", level);
                    agent.on_timeout(level);
                    future::ok(())
                })).into_future()
            };

            let updates = {
                let updates = Interval::new_interval(agent.config.update_period);
                let agent = Arc::clone(&agent);
                tokio::spawn(updates
                    .map_err(|e| {
                        error!("Interval error: {}", e);
                    })
                    .for_each(move |t| {
                        //debug!("Periodic update: {:?}", t);
                        agent.on_update();
                        future::ok::<(), ()>(())
                    })
                ).into_future()
            };

            timeouts
                .join(updates)
                .map(|_| ())
        }))
    }
}



impl Handler for Arc<HandelAgent> {
    fn on_message(&self, message: Message, sender_address: SocketAddr) -> Box<dyn Future<Item=(), Error=IoError> + Send> {
        // we create a future that handles the message
        let handle_fut = if !self.state.read().done {
            // deconstruct message
            let Message {
                origin,
                level,
                multisig,
                individual,
            } = message;
            let origin = origin as usize;
            let level = level as usize;

            info!("Received message from address={} id={} for level={}", sender_address, origin, level);

            // XXX The following code should all be a future. The part that takes ultimately the
            //     longest will be the signature checking, so we could distribute that over a
            //     CPU pool.

            // Creates a future that will verify the multisig on a CpuPool and then push it into
            // the TODOs
            let this = Arc::clone(&self);
            let multisig_fut = self.verifier.verify_multisig(multisig.clone())
                .and_then(move|result| {
                    if result == VerifyResult::Ok {
                        this.state.write().todos.push(Todo::Multi { signature: multisig, level });
                    }
                    else {
                        warn!("Rejected signature: {:?}", result);
                    }
                    Ok(())
                });

            // Creates a future that will verify the individual signature on a CpuPool and then
            // push it into the TODOs
            let this = Arc::clone(&self);
            let individual_fut = if let Some(sig) = individual {
                Either::A(self.verifier.verify_individual(sig.clone(), origin)
                    .and_then(move |result| {
                        if result == VerifyResult::Ok {
                            this.state.write().todos.push(Todo::Individual{ signature: sig, level, origin });
                        }
                        else {
                            warn!("Rejected signature: {:?}", result);
                        }
                        Ok(())
                    }))
            } else {
                Either::B(future::ok::<(), ()>(()))
            };

            // Creates a future that will first verify the signatures and then gets all good TODOs
            // and applys them
            let this = Arc::clone(&self);
            let process_fut = multisig_fut
                .join(individual_fut)
                .and_then(move |_| {
                    let mut state = this.state.write();

                    // continuously put best todo into store, until there is no good one anymore
                    while let Some((todo, score)) = state.get_best_todo() {
                        // TODO: put signature from todo into store - is this correct?
                        todo.put(&mut state.store);
                    }
                    Ok(())
                })
                .map_err(|e| {
                    // Technically nothing here can fail, but we need to handle that case anyway
                    warn!("The signature processing future somehow failed: {:?}", e);
                    IoError::from(ErrorKind::ConnectionReset)
                });

            Either::A(process_fut)
        }
        else {
            // we're done, so we don't care
            Either::B(future::failed(IoError::from(ErrorKind::ConnectionReset)))
        };

        // box it, so we don't have to bother about the return type
        Box::new(handle_fut)
    }

}
