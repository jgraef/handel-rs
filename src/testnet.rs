use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration};

use rand_chacha::ChaChaRng;
use rand::SeedableRng;
use futures::{future, Future, IntoFuture};
use stopwatch::Stopwatch;

use bls::bls12_381::KeyPair;
use hash::{Hash, Blake2bHash};

use crate::handel::{
    IdentityRegistry, Identity, Config, UdpNetwork, HandelAgent, AgentProcessor,
};



pub struct TestNet {
    pub num_nodes: usize,
    key_pairs: Vec<KeyPair>,
}

impl TestNet {
    pub fn new(num_nodes: usize, seed: [u8; 32]) -> TestNet {
        // generate key pairs
        let mut csprng = ChaChaRng::from_seed(seed);
        let mut key_pairs = Vec::new();
        for _ in 0..num_nodes {
            key_pairs.push(KeyPair::generate(&mut csprng));
        }

        TestNet {
            num_nodes,
            key_pairs,
        }
    }

    pub fn key_pair(&self, id: usize) -> KeyPair {
        self.key_pairs.get(id)
            .unwrap_or_else(|| panic!("No keypair for ID {}", id))
            .clone()
    }

    pub fn identity(&self, id: usize) -> Identity {
        Identity::new(
            id,
            self.key_pair(id).public,
            SocketAddr::new("127.0.0.1".parse().unwrap(), (12000 + id) as u16),
            1
        )
    }

    pub fn identity_registry(&self) -> IdentityRegistry {
        let mut registry = IdentityRegistry::new();

        for id in 0..self.num_nodes {
            registry.insert(Arc::new(self.identity(id)));
        }

        registry
    }

    pub fn threshold(&self) -> usize {
        (2 * self.num_nodes) / 3
    }

    pub fn config(&self, id: usize) -> Config {
        Config {
            threshold: self.threshold(),
            message_hash: b"foobar".hash::<Blake2bHash>(),
            node_identity: Arc::new(self.identity(id)),
            disable_shuffling: false,
            update_count: 1,
            update_period: Duration::from_millis(100),
            timeout: Duration::from_millis(500),
            peer_count: 10,
            key_pair: self.key_pair(id),
        }
    }

    pub fn create_node(&self, id: usize) -> Box<dyn Future<Item=(), Error=()> + Send>{
        let identity = self.identity(id);

        // start network layer
        let mut network = UdpNetwork::new();
        let stats = Arc::clone(&network.statistics);
        let bind_to = SocketAddr::new(
            "0.0.0.0".parse().expect("Invalid IP address"),
            identity.address.port()
        );

        // initialize agent
        let agent = Arc::new(HandelAgent::new(self.config(id), self.identity_registry(), network.sink()));


        Box::new(future::lazy(move|| {
            let mut stopwatch = Stopwatch::start_new();

            tokio::spawn(network
                .connect(&bind_to, Arc::clone(&agent))
                .expect("Failed to initialize network")
                .join(agent.spawn()).map(|_| ())
                .and_then(move |_| {
                    let agent = Arc::clone(&agent);
                    agent.final_signature().unwrap()
                        .map_err(|e| error!("Final signature error: {}", e))
                        .and_then(move |result| {
                            stopwatch.stop();

                            match result {
                                Ok(signature) => {
                                    info!("[Node {}] Finished with signature: {:#?}", id, signature);
                                    let stats = stats.read();
                                    info!("[Node {}] Stats: time={}, signatures={}, sent={}, received={}", id, stopwatch.elapsed_ms(), signature.len(), stats.sent_count, stats.received_count);
                                },
                                Err(e) => error!("[Node {}] Finished with error: {:?}", id, e),
                            }

                            future::ok::<(), ()>(())
                        })
                })
            ).into_future()
        }))
    }
}
