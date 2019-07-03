use std::sync::Arc;
use std::time::Duration;

use hash::Blake2bHash;
use bls::bls12_381::{KeyPair, Signature};

use crate::handel::Identity;


#[derive(Clone, Debug)]
pub struct Config {
    /// Number of signatures needed to consider the multisig valid
    pub threshold: usize,

    /// Hash of the message that is being signed
    pub message_hash: Blake2bHash,

    /// The identity of this node
    pub node_identity: Arc<Identity>,

    /// Whether to disable shuffling of identities per level
    pub disable_shuffling: bool,

    /// Number of peers contacted during an update at each level
    pub update_count: usize,

    /// Frequency at which updates are sent to peers
    pub update_period: Duration,

    /// Timeout for levels
    pub timeout: Duration,

    /// How many peers are contacted at each level ???
    pub peer_count: usize,

    /// Key pair for signing the message
    pub key_pair: KeyPair,
}

impl Config {
    pub fn individual_signature(&self) -> Signature {
        self.key_pair.sign_hash(self.message_hash.clone())
    }
}