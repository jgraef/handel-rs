use hash::Blake2bHash;


pub struct Config {
    /// Number of signatures needed to consider the multisig valid
    threshold: usize,

    /// Hash of the message that is being signed
    message_hash: Blake2bHash,
}

