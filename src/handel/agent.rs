use std::sync::Arc;
use std::net::SocketAddr;
use std::io::Error as IoError;
use std::io::ErrorKind;

use parking_lot::{RwLock, RwLockUpgradableReadGuard, RwLockWriteGuard};
use futures::{Future, future, Stream, IntoFuture};
use futures::future::Either;
use tokio::timer::Interval;
use futures::sync::mpsc::{SendError, UnboundedSender};
use futures::sync::oneshot::{Sender, channel, Receiver};

use beserial::Serialize;
use bls::bls12_381::Signature;

use crate::handel::{
    IdentityRegistry, Message, Config, BinomialPartitioner, Level, MultiSignature, Handler,
    SignatureStore, ReplaceStore, VerifyResult, LinearTimeout, TimeoutStrategy, DummyVerifier,
    Verifier, ThreadPoolVerifier
};


#[derive(Clone, Debug)]
enum Todo {
    Individual { signature: Signature, level: usize, origin: usize },
    Multi { signature: MultiSignature, level: usize, votes: usize }
}

impl Todo {
    pub fn evaluate(&self, store: &ReplaceStore) -> usize {
        match self {
            Todo::Multi { signature, level, votes } => store.evaluate_multisig(signature, *level, *votes),
            Todo::Individual { signature, level, origin } => store.evaluate_individual(signature, *level, *origin)
        }
    }

    pub fn put(self, store: &mut ReplaceStore) {
        match self {
            Todo::Individual { signature, level, origin } => {
                store.put_individual(signature, level, origin)
            }
            Todo::Multi { signature, level, votes: _ } => {
                store.put_multisig(signature, level)
            }
        }
    }

    pub fn level(&self) -> usize {
        *match self {
            Todo::Individual { signature: _, level, origin: _ } => level,
            Todo::Multi { signature: _, level, votes: _ } => level,
        }
    }
}



pub struct HandelState {
    pub done: bool,
    todos: Vec<Todo>,
    pub store: ReplaceStore,
}

type HandelResult = Result<MultiSignature, ()>;

pub struct HandelAgent {
    /// State that is modified from multiple threads
    state: RwLock<HandelState>,

    /// Handel configuration
    config: Config,

    /// All known identities
    identities: Arc<IdentityRegistry>,

    /// Multi-threaded signature verification
    verifier: DummyVerifier,
    //verifier: ThreadPoolVerifier,

    /// Sink to send messages to other peers
    sink: UnboundedSender<(Message, SocketAddr)>,

    /// Level timeouts
    timeouts: LinearTimeout,

    /// Our individual signature
    individual: Signature,

    /// Levels
    levels: Vec<Level>,

    /// Channel to pass final signature
    result_sender: RwLock<Option<Sender<HandelResult>>>,
    result_receiver: RwLock<Option<Receiver<HandelResult>>>,
}


impl HandelAgent {
    pub fn new(config: Config, identities: IdentityRegistry, sink: UnboundedSender<(Message, SocketAddr)>) -> HandelAgent {
        /*info!("New Handel Agent:");
        info!(" - ID: {}", config.node_identity.id);
        info!(" - Address: {}", config.node_identity.address);
        info!(" - Public Key: {}", hex::encode(config.node_identity.public_key.serialize_to_vec()));*/

        /*info!("Identities (n={}):", identities.len());
        let mut max_id = 0;
        for identity in identities.all().iter() {
            let pk_hex = &hex::encode(identity.public_key.serialize_to_vec())[0..8];
            info!(" {:>5}: address={}, pubkey={}, weight={}", identity.id, identity.address, pk_hex, identity.weight);
            max_id = max_id.max(identity.id);
        }*/
        let max_id = identities.all().iter()
            .map(|identity| identity.id)
            .max()
            .expect("No identities");

        // initialize EVERYTHING!
        let identities = Arc::new(identities);
        let partitioner = Arc::new(BinomialPartitioner::new(config.node_identity.id, max_id));
        let levels = Level::create_levels(&config, Arc::clone(&partitioner));
        let store = ReplaceStore::new(Arc::clone(&partitioner));
        //let verifier = ThreadPoolVerifier::new(config.threshold, config.message_hash.clone(), Arc::clone(&identities), None);
        let verifier = DummyVerifier::new(config.threshold, Arc::clone(&identities));
        let individual = config.individual_signature();
        let timeouts = LinearTimeout::new(config.timeout);
        let (result_sender, result_receiver) = channel();

        HandelAgent {
            state: RwLock::new(HandelState {
                done: false,
                todos: Vec::new(),
                store,
            }),
            config,
            identities,
            verifier,
            sink,
            timeouts,
            individual,
            levels,
            result_sender: RwLock::new(Some(result_sender)),
            result_receiver: RwLock::new(Some(result_receiver)),
        }
    }

    pub fn final_signature(&self) -> Option<Receiver<HandelResult>> {
        self.result_receiver.write().take()
    }

    fn send_to(&self, to: Vec<usize>, multisig: MultiSignature, individual: Option<Signature>, level: usize) -> Result<(), SendError<(Message, SocketAddr)>> {
        let message = Message {
            origin: self.config.node_identity.id as u16,
            level: level as u8,
            multisig,
            individual,
        };

        //debug!("Sending to {:?}: {:?}", to, message);

        for id in to {
            if id == self.config.node_identity.id {
                continue;
            }
            if let Some(identity) = self.identities.get_by_id(id) {
                self.sink.unbounded_send((message.clone(), identity.address.clone()))?;
            }
            else {
                error!("Unknown identity: id={}", id);
            }
        }

        Ok(())
    }

    fn on_timeout(&self, level: usize) {
        self.start_level(level);
    }

    fn start_level(&self, level: usize) {
        debug!("Starting level {}", level);

        let level = self.levels.get(level)
            .unwrap_or_else(|| panic!("Timeout for invalid level {}", level));

        level.start();
        if level.id > 0 {
            if let Some(best) = self.state.read().store.combined(level.id - 1) {
                self.send_update(best, level, self.config.peer_count);
            }
        }

    }

    /// Periodic update:
    ///  - check if timeout for level is reached. TODO: This is done with `on_timeout`
    ///  - send a new packet ???
    fn on_update(&self) {
        let state = self.state.read();

        // NOTE: Skip level 0
        for level in self.levels.iter().skip(1) {
            //debug!("send update for level {}", level.id);
            // send update
            if let Some(multisig) = state.store.combined(level.id - 1) {
                self.send_update(multisig, &level, self.config.update_count);
            }
        }
    }

    fn check_completed_level(&self, todo: &Todo) {
        debug!("check_completed_level: {:?}", todo);

        if let Some(level) = self.levels.get(todo.level()) {
            let state = self.state.read();

            {
                let mut level_state = level.state.write();

                if level_state.receive_completed {
                    debug!("check_completed_level: receive_completed=true");
                    return
                }

                let best = state.store.best(todo.level())
                    .unwrap_or_else(|| panic!("We should have received the best signature for level {}", todo.level()));

                debug!("check_completed_level: level={}, best.len={}, num_peers={}", level.id, best.len(), level.num_peers());
                if best.len() == level.num_peers() {
                    //info!("Level {} complete", todo.level());
                    level_state.receive_completed = true;

                    if todo.level() + 1 < self.levels.len() {
                        // activate next level
                        self.start_level(todo.level() + 1)
                    }
                }
            }

            for i in todo.level() + 1 .. self.levels.len() {
                if let Some(multisig) = state.store.combined(i - 1) {
                    let level = self.levels.get(i)
                        .unwrap_or_else(|| panic!("No level {}", i));
                    if level.update_signature_to_send(&multisig) {
                        self.send_update(multisig, &level, self.config.peer_count);
                    }
                }
            }
        }
        else {
            error!("Invalid level: {}", todo.level());
        }
    }

    fn check_final_signature(&self, _todo: &Todo) {
        let last_level = self.levels.last().expect("No levels");
        let state = self.state.upgradable_read();

        if let Some(combined) = state.store.combined(last_level.id) {
            if combined.len() > self.config.threshold {
                debug!("Last level combined: {:#?}", combined);
                if let Some(sender) = self.result_sender.write().take() {
                    info!("Last level finished receiving");

                    // set done to true
                    let mut state = RwLockUpgradableReadGuard::upgrade(state);
                    state.done = true;
                    let state = RwLockWriteGuard::downgrade(state);

                    sender.send(Ok(combined))
                        .unwrap_or_else(|_| error!("Sending final signature to future failed"));
                }
                else {
                    warn!("Already produced final signature");
                }
            }
        }
    }

    fn send_update(&self, multisig: MultiSignature, level: &Level, count: usize) {
        let peer_ids = level.select_next_peers(count);

        let individual = if level.state.read().receive_completed { None } else { Some(self.individual.clone()) };

        self.send_to(peer_ids, multisig, individual, level.id)
            .unwrap_or_else(|e| error!("Failed to send message to {}", e.into_inner().1))
    }

    fn get_best_todo(&self) -> Option<(Todo, usize)> {
        let state = self.state.upgradable_read();

        let mut best_i = 0;
        let mut best_score = state.todos.first()?.evaluate(&state.store);

        for (i, todo) in state.todos.iter().enumerate().skip(1) {
            let score = todo.evaluate(&state.store);
            if score > best_score {
                best_i = i;
                best_score = score;
            }
        }

        //debug!("Best score: {}", best_score);
        if best_score > 0 {
            let mut state = RwLockUpgradableReadGuard::upgrade(state);
            let best_todo = state.todos.swap_remove(best_i);
            Some((best_todo, best_score))
        }
        else {
            None
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
            // thread that handles level timeouts
            let timeouts = {
                let timeouts = agent.timeouts.timeouts(agent.levels.len());
                let agent = Arc::clone(&agent);
                tokio::spawn(timeouts.for_each(move |level| {
                    //debug!("Timeout for level {}", level);
                    agent.on_timeout(level);
                    future::ok(())
                }))
            };

            // thread that periodically updates levels
            let updates = {
                let updates = Interval::new_interval(agent.config.update_period);
                let agent = Arc::clone(&agent);
                tokio::spawn(updates
                    .map_err(|e| {
                        error!("Interval error: {}", e);
                    })
                    .for_each(move |_instant| {
                        //debug!("Periodic update: {:?}", t);
                        agent.on_update();
                        future::ok::<(), ()>(())
                    })
                )
            };

            // future that will put our own individual signature into store and notify the agent
            let init = {
                let agent = Arc::clone(&agent);
                future::lazy(move || {
                    let mut state = agent.state.write();

                    // put own individual signature into store
                    //state.store.put_individual(agent.individual.clone(), 0, agent.config.node_identity.id);
                    //state.store.put_multisig(MultiSignature::from_individual(&agent.individual, agent.config.node_identity.id), 0);
                    let todo = Todo::Individual { signature: agent.individual.clone(), level: 0, origin: agent.config.node_identity.id };
                    todo.clone().put(&mut state.store);

                    drop(state);

                    // notify
                    agent.check_completed_level(&todo);
                    agent.check_final_signature(&todo);

                    // send level 0
                    let level = agent.levels.get(0)
                        .expect("Level 0 missing");
                    agent.send_update(MultiSignature::from_individual(&agent.individual, agent.config.node_identity.id), level, agent.config.peer_count);

                    future::ok::<(), ()>(())
                })
            };


            init.and_then(|_| {
                timeouts.into_future()
                    .join(updates.into_future())
                    .map(|_| ())
            })
        }))
    }
}



impl Handler for Arc<HandelAgent> {
    fn on_message(&self, message: Message, _sender_address: SocketAddr) -> Box<dyn Future<Item=(), Error=IoError> + Send> {
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

            if let Some(level) = self.levels.get(level) {
                if level.state.read().receive_completed {
                    return Box::new(future::ok::<(), IoError>(()));
                }
            }
            else {
                error!("Invalid level in message: {}", level);
            }

            //info!("Received message from address={} id={} for level={}", sender_address, origin, level);

            // XXX The following code should all be a future. The part that takes ultimately the
            //     longest will be the signature checking, so we could distribute that over a
            //     CPU pool.

            // Creates a future that will verify the multisig on a CpuPool and then push it into
            // the TODOs
            let this = Arc::clone(&self);
            let multisig_fut = self.verifier.verify_multisig(multisig.clone(), false)
                .and_then(move|result| {
                    match result {
                        VerifyResult::Ok { votes } => {
                            this.state.write().todos.push(Todo::Multi { signature: multisig, level, votes });
                        },
                        _ => {
                            warn!("Rejected signature: {:?}", result);
                            warn!("{:#?}", multisig);
                        }
                    }
                    Ok(())
                });

            // Creates a future that will verify the individual signature on a CpuPool and then
            // push it into the TODOs
            let this = Arc::clone(&self);
            let individual_fut = if let Some(sig) = individual {
                Either::A(self.verifier.verify_individual(sig.clone(), origin)
                    .and_then(move |result| {
                        match result {
                            VerifyResult::Ok { votes } => {
                                assert_eq!(votes, 1);
                                this.state.write().todos.push(Todo::Individual{ signature: sig, level, origin });
                            },
                            _ => {
                                warn!("Rejected signature: {:?}", result);
                                warn!("{:#?}", sig);
                            }
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
                    // continuously put best todo into store, until there is no good one anymore
                    while let Some((todo, score)) = this.get_best_todo() {
                        //info!("Processing: score={}: {:?}", score, todo);
                        // TODO: put signature from todo into store - is this correct?
                        todo.clone().put(&mut this.state.write().store);
                        this.check_completed_level(&todo);
                        this.check_final_signature(&todo);
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
            //Either::B(future::failed(IoError::from(ErrorKind::ConnectionReset)))
            Either::B(future::ok::<(), IoError>(()))
        };

        // box it, so we don't have to bother about the return type
        Box::new(handle_fut)
    }

}
