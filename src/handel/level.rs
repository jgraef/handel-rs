use std::sync::Arc;
use std::cmp::min;

use crate::network::Peer;
use crate::handel::MultiSignature;


#[derive(Debug, Clone)]
pub struct Level {
    id: usize,
    peers: Vec<Arc<Peer>>,
    send_started: bool,
    receive_completed: bool,
    send_peers_pos: usize,
    send_peers_count: usize,
    send_expected_full_size: usize,
    send_signature_size: usize,
    //best_incoming: AggregateSignature,
    //best_outgoing: AggregateSignature,
}

impl Level {
    pub fn new(id: usize, peers: Vec<Arc<Peer>>, send_expected_full_size: usize) -> Level {
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

    pub fn create_levels() -> Vec<Level> {
        unimplemented!()
    }

    pub fn active(&self) -> bool {
        self.started() && self.send_peers_count < self.peers.len()
    }

    pub fn started(&self) -> bool {
        self.send_started
    }

    pub fn select_next_peers(&mut self, count: usize) -> Vec<Arc<Peer>> {
        let size = min(count, self.peers.len());
        let mut selected: Vec<Arc<Peer>> = Vec::new();

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