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
    SignatureStore, ReplaceStore, Verifier, VerifyResult
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
    state: RwLock<HandelState>,
    config: Config,
    identities: Arc<IdentityRegistry>,
    partitioner: Arc<BinomialPartitioner>,
    levels: Vec<Level>,
    verifier: Verifier
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
            info!(" {:>5}: address={}, pubkey={}, weight={}", identity.id, identity.address, pk_hex, identity.weight);
            max_id = max_id.max(identity.id);
        }

        let identities = Arc::new(identities);
        let partitioner = Arc::new(BinomialPartitioner::new(config.node_identity.id, max_id));
        let levels = Level::create_levels(&config, Arc::clone(&partitioner));
        let store = ReplaceStore::new(Arc::clone(&partitioner));
        let verifier = Verifier::new(config.threshold, config.message_hash.clone(), Arc::clone(&identities));

        HandelAgent {
            state: RwLock::new(HandelState {
                done: false,
                todos: Vec::new(),
                store,
            }),
            config,
            identities,
            partitioner,
            levels,
            verifier,
        }
    }
}


impl Handler for Arc<HandelAgent> {
    type Result = Result<(), IoError>;

    fn on_message(&self, message: Message, sender_address: SocketAddr) -> Self::Result {
        let mut state = self.state.write();

        if !state.done {
            // deconstruct message
            let Message {
                origin,
                level,
                multisig,
                individual,
            } = message;

            info!("Received message from address={} id={} for level={}", sender_address, origin, level);

            // XXX The following code should all be a future. The part that takes ultimately the
            //     longest will be the signature checking, so we could distribute that over a
            //     CPU pool.


            state.todos.push(Todo::Multi { signature: multisig, level: level as usize });

            if let Some(sig) = individual {
                // XXX I think the reference implementation does the verification somewhere else
                if self.verifier.verify_individual(&sig, origin as usize) == VerifyResult::Ok {
                    state.todos.push(Todo::Individual{ signature: sig, level: level as usize, origin: origin as usize });
                }
            }

            // continously put best todo into store, until there is no good one anymore
            while let Some((todo, score)) = state.get_best_todo() {
                // TODO: put signature from todo into store - is this correct?
                todo.put(&mut state.store);
            }

            Ok(())
        }
        else {
            // TODO: is that the correct error or should we fail at all?
            Err(IoError::from(ErrorKind::ConnectionReset))
        }
    }
}
