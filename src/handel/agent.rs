use parking_lot::RwLock;
use std::sync::Arc;
use std::net::SocketAddr;
use std::io::Error as IoError;

use beserial::Serialize;

use crate::handel::{
    Identity, IdentityRegistry, Message, Handler, Config, BinomialPartitioner, Level
};



pub struct HandelState {
    done: bool,
    identities: Arc<IdentityRegistry>,
    partitioner: BinomialPartitioner,
    levels: Vec<Level>,
}


pub struct HandelAgent {
    state: RwLock<HandelState>,
    config: Config,
}


impl HandelAgent {
    pub fn new(config: Config, identities: IdentityRegistry) -> HandelAgent {
        info!("New Handel Agent:");
        info!(" - ID: {}", config.node_identity.id);
        info!(" - Address: {}", config.node_identity.address);
        info!(" - Public Key: {}", hex::encode(config.node_identity.public_key.serialize_to_vec()));

        info!("Identities:");
        for identity in identities.all().iter() {
            let pk_hex = &hex::encode(identity.public_key.serialize_to_vec())[0..8];
            info!(" {:>5}: {} - {}", identity.id, identity.address, pk_hex);
        }

        let identities = Arc::new(identities);
        let partitioner = BinomialPartitioner::new(config.node_identity.id, Arc::clone(&identities));
        let levels = Level::create_levels(&config, &partitioner);

        HandelAgent {
            state: RwLock::new(HandelState {
                done: false,
                identities,
                partitioner,
                levels,
            }),
            config,
        }
    }
}

impl Handler for Arc<RwLock<HandelAgent>> {
    fn on_message(&mut self, message: Message, sender_address: SocketAddr) -> Result<(), IoError> {
        Ok(())
    }
}
