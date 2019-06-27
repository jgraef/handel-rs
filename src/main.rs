#[macro_use]
extern crate log;
extern crate simple_logger;

extern crate tokio;
extern crate futures;
extern crate bytes;

extern crate beserial;
#[macro_use]
extern crate beserial_derive;
extern crate nimiq_bls as bls;
extern crate nimiq_collections as collections;
extern crate nimiq_hash as hash;
extern crate nimiq_block_albatross as block;

mod handel;
mod network;


use futures::Future;
use log::Level;

use network::Node;



fn main() {
    simple_logger::init_with_level(Level::Debug)
        .expect("Failed to initialize Logging");

    let bind_to = "0.0.0.0:1337".parse().unwrap();
    let task = Node::handle_messages(&bind_to);

    tokio::run(task
        .map_err(|e| {
            error!("Error?");
        })
        .map(|_| {
            // nop
            info!("Done");
        })
    )
}
