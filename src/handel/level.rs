use std::sync::Arc;
use std::cmp::min;

use rand::{Rng, thread_rng};

use crate::handel::{MultiSignature, Identity, IdentityRegistry, BinomialPartitioner, Config};
use rand::seq::SliceRandom;


#[derive(Debug, Clone)]
pub struct Level {
    id: usize,
    peer_ids: Vec<usize>,
    send_started: bool,
    receive_completed: bool,
    send_peers_pos: usize,
    send_peers_count: usize,
    send_expected_full_size: usize,
    send_signature_size: usize,
}

impl Level {
    pub fn new(id: usize, peer_ids: Vec<usize>, send_expected_full_size: usize) -> Level {
        Level {
            id,
            peer_ids,
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

        for i in 0..partitioner.num_levels {
            debug!("Creating level {}", i);

            // This unwrap is safe, since we only iterate until `num_levels - 1`
            let mut ids: Vec<usize> = partitioner.range(i).unwrap().collect();

            debug!("Number of identities: {}", ids.len());

            if !config.disable_shuffling {
                ids.shuffle(&mut rng);
                let size = ids.len();
                let mut level = Level::new(i, ids, send_expected_full_size);

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
        self.send_started && self.send_peers_count < self.peer_ids.len()
    }

    pub fn select_next_peers(&mut self, count: usize) -> Vec<usize> {
        let size = min(count, self.peer_ids.len());
        let mut selected: Vec<usize> = Vec::new();

        for i in 0..size {
            // NOTE: Unwrap is safe, since we make sure at least `size` elements are in `self.peers`
            selected.push(*self.peer_ids.get(self.send_peers_pos).unwrap());
            self.send_peers_pos += 1;
            if self.send_peers_pos >= self.peer_ids.len() {
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