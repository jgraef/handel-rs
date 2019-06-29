use std::sync::Arc;
use std::cmp::min;

use rand::{Rng, thread_rng};

use crate::handel::{MultiSignature, Identity, BinomialPartitioner, Config};
use rand::seq::SliceRandom;


#[derive(Debug, Clone)]
pub struct Level {
    id: usize,
    peers: Vec<Arc<Identity>>,
    send_started: bool,
    receive_completed: bool,
    send_peers_pos: usize,
    send_peers_count: usize,
    send_expected_full_size: usize,
    send_signature_size: usize,
}

impl Level {
    pub fn new(id: usize, peers: Vec<Arc<Identity>>, send_expected_full_size: usize) -> Level {
        Level {
            id,
            peers,
            send_started: false,
            receive_completed: false,
            send_peers_pos: 0,
            send_peers_count: 0,
            send_expected_full_size,
            send_signature_size: 0
        }
    }

    pub fn create_levels(config: &Config, partitioner: &BinomialPartitioner) -> Vec<Level> {
        let mut levels: Vec<Level> = Vec::new();
        let mut first_active = false;
        let mut send_expected_full_size: usize = 1;
        let mut rng = thread_rng();

        for i in partitioner.levels() {
            debug!("Creating level {}", i);
            let mut identities = partitioner.identities_at(i)
                .expect("There should be identities at the given level");
            debug!("Number of identities: {}", identities.len());
            if !config.disable_shuffling {
                identities.shuffle(&mut rng);
                let size = identities.len();
                let mut level = Level::new(i, identities, send_expected_full_size);

                if !first_active {
                    first_active = true;
                    level.send_started = true;
                }

                levels.push(level);
                send_expected_full_size += size;
            }
        }

        levels
    }

    pub fn active(&self) -> bool {
        self.send_started && self.send_peers_count < self.peers.len()
    }

    pub fn select_next_peers(&mut self, count: usize) -> Vec<Arc<Identity>> {
        let size = min(count, self.peers.len());
        let mut selected: Vec<Arc<Identity>> = Vec::new();

        for i in 0..size {
            // NOTE: Unwrap is safe, since we make sure at least `size` elements are in `self.peers`
            selected.push(Arc::clone(self.peers.get(self.send_peers_pos).unwrap()));
            self.send_peers_pos += 1;
            if self.send_peers_pos >= self.peers.len() {
                self.send_peers_pos = 0;
            }
        }

        selected
    }

    pub fn update_signature_to_send(&mut self, signature: &MultiSignature) -> bool {
        if self.send_signature_size >= signature.num_signers {
            return false;
        }

        self.send_signature_size = signature.num_signers;
        self.send_peers_count = 0;

        if self.send_signature_size == self.send_expected_full_size {
            self.send_started = true;
            return true;
        }

        false
    }
}