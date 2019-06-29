use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use std::sync::Arc;
use std::net::SocketAddr;
use std::io::Error as IoError;
use std::io::ErrorKind;

use beserial::Serialize;
use bls::bls12_381::{AggregateSignature, Signature};

use crate::handel::{
    Identity, IdentityRegistry, Message, Handler, Config, BinomialPartitioner, Level
};


pub struct HandelAgent {
    config: Config,
    done: bool,
    identities: Arc<IdentityRegistry>,
    partitioner: BinomialPartitioner,
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
        let partitioner = BinomialPartitioner::new(config.node_identity.id, max_id);
        let levels = Level::create_levels(&config, &partitioner);

        HandelAgent {
            config,
            done: false,
            identities,
            partitioner,
            levels,
        }
    }

    pub fn on_message(&mut self, message: Message, sender_address: SocketAddr) -> Result<(), IoError> {
        if !self.done && !self.levels.get(message.level as usize)
            .ok_or_else(|| IoError::from(ErrorKind::InvalidInput))?.receive_completed {
            self.add_aggregate_signature(&message.aggregate_signature);
            self.add_individual_signature(&message.individual_signature);

        }
        Ok(())
    }

    pub fn add_aggregate_signature(&mut self, signature: &AggregateSignature) {
        unimplemented!()
    }

    pub fn add_individual_signature(&mut self, signature: &Signature) {
        unimplemented!()
    }
}

impl Handler for Arc<RwLock<HandelAgent>> {
    fn on_message(&self, message: Message, sender_address: SocketAddr) -> Result<(), IoError> {
        self.write().on_message(message, sender_address)
    }
}
