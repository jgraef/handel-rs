use std::sync::Arc;

use hash::Blake2bHash;

use crate::handel::Identity;


pub struct Config {
    /// Number of signatures needed to consider the multisig valid
    pub threshold: usize,

    /// Hash of the message that is being signed
    pub message_hash: Blake2bHash,

    pub node_identity: Arc<Identity>,
}

