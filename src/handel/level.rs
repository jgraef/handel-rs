use std::cmp::min;
use std::sync::Arc;

use rand::thread_rng;
use parking_lot::RwLock;

use crate::handel::{MultiSignature, BinomialPartitioner, Config};
use rand::seq::SliceRandom;


#[derive(Clone, Debug)]
pub struct LevelState {
    pub send_started: bool,
    pub receive_completed: bool,
    pub send_peers_pos: usize,
    pub send_signature_size: usize,
    pub send_peers_count: usize,
}

#[derive(Debug)]
pub struct Level {
    pub id: usize,
    pub peer_ids: Vec<usize>,
    pub send_expected_full_size: usize,
    pub state: RwLock<LevelState>
}

impl Level {
    pub fn new(id: usize, peer_ids: Vec<usize>, send_expected_full_size: usize) -> Level {
        Level {
            id,
            peer_ids,
            send_expected_full_size,
            state: RwLock::new(LevelState {
                send_started: false,
                receive_completed: false,
                send_peers_pos: 0,
                send_signature_size: 0,
                send_peers_count: 0,
            })
        }
    }

    pub fn num_peers(&self) -> usize {
        self.peer_ids.len()
    }

    pub fn create_levels(config: &Config, partitioner: Arc<BinomialPartitioner>) -> Vec<Level> {
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
            }

            let size = ids.len();
            let mut level = Level::new(i, ids, send_expected_full_size);

            if !first_active {
                first_active = true;
                level.state.write().send_started = true;
            }

            levels.push(level);
            send_expected_full_size += size;
        }

        levels
    }

    pub fn active(&self) -> bool {
        let state = self.state.read();
        state.send_started && state.send_peers_count < self.peer_ids.len()
    }

    pub fn select_next_peers(&self, count: usize) -> Vec<usize> {
        let size = min(count, self.peer_ids.len());
        let mut selected: Vec<usize> = Vec::new();

        let mut state = self.state.write();
        for _ in 0..size {
            // NOTE: Unwrap is safe, since we make sure at least `size` elements are in `self.peers`
            selected.push(*self.peer_ids.get(state.send_peers_pos).unwrap());
            state.send_peers_pos += 1;
            if state.send_peers_pos >= self.peer_ids.len() {
                state.send_peers_pos = 0;
            }
        }

        selected
    }

    pub fn update_signature_to_send(&self, signature: &MultiSignature) -> bool {
        let mut state = self.state.write();

        if state.send_signature_size >= signature.len() {
            return false;
        }

        state.send_signature_size = signature.len();
        state.send_peers_count = 0;

        if state.send_signature_size == self.send_expected_full_size {
            state.send_started = true;
            return true;
        }

        false
    }
}
