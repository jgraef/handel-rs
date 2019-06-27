use parking_lot::RwLock;

use crate::handel::Config;


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