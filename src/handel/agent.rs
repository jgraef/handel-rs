use parking_lot::RwLock;
use std::sync::Arc;
use std::net::SocketAddr;
use std::io::Error as IoError;

use crate::handel::Config;
use crate::handel::{Identity, IdentityRegistry, Message, Handler};


pub struct HandelState {
    done: bool,
}


pub struct HandelAgent {
    state: RwLock<HandelState>,
    config: Config,
}


impl HandelAgent {
    pub fn new(config: Config) -> HandelAgent {
        HandelAgent {
            state: RwLock::new(HandelState {
                done: false,
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
