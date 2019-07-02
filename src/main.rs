#[macro_use]
extern crate log;
extern crate simple_logger;
#[macro_use]
extern crate clap;
extern crate tokio;
extern crate futures;
extern crate bytes;
extern crate failure;
extern crate hex;
extern crate futures_cpupool;

extern crate beserial;
#[macro_use]
extern crate beserial_derive;
extern crate nimiq_bls as bls;
extern crate nimiq_collections as collections;
extern crate nimiq_hash as hash;
extern crate nimiq_block_albatross as block;


mod handel;


use std::io::Error as IoError;
use std::net::SocketAddr;
use std::sync::Arc;
use std::error::Error;

use futures::{Future, Stream};
use log::Level;
use clap::{App, Arg};
use rand::rngs::OsRng;

use beserial::Deserialize;
use hash::{Hash, Blake2bHash};
use bls::bls12_381::{PublicKey, KeyPair, SecretKey};

use crate::handel::{
    UdpNetwork, IdentityRegistry, HandelAgent, Config, Identity, Handler, AgentProcessor
};


fn run_app() -> Result<(), Box<dyn Error>> {
    // parse command line
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::with_name("id")
            .long("id")
            .value_name("ID")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("secret_key")
            .long("secret-key")
            .value_name("SECRETKEY")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("address")
            .long("address")
            .value_name("ADDRESS")
            .takes_value(true)
            .default_value("127.0.0.1:1337"))
        .arg(Arg::with_name("port")
            .long("port")
            .value_name("PORT")
            .takes_value(true)
            .default_value("1337"))
        .arg(Arg::with_name("threshold")
            .long("threshold")
            .value_name("THRESHOLD")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("message")
            .long("message")
            .value_name("MESSAGE")
            .takes_value(true)
            .required(true))
        .get_matches();

    // parse secret key
    let sk_raw = hex::decode(matches.value_of("secret_key").expect("No secret key"))?;
    let key_pair: KeyPair = Deserialize::deserialize_from_vec(&sk_raw)
        .map_err(|e| IoError::from(e))?;

    // create handel config from command line
    let config = Config {
        threshold: matches.value_of("threshold").expect("No threshold").parse()?,
        message_hash: matches.value_of("message").expect("No message").hash::<Blake2bHash>(),
        node_identity: Arc::new(Identity::new(
            matches.value_of("id").expect("No ID").parse()?,
            key_pair.public,
            matches.value_of("address").expect("No address").parse()?,
            1
        )),
        disable_shuffling: true,
    };

    // fill `IdentityRegistry` with some mock data
    let mut csprng = OsRng::new().expect("OS RNG not available");
    let mut identities = IdentityRegistry::new();
    for i in 0..16 {
        let secret_key = SecretKey::generate(&mut csprng);
        identities.insert(Arc::new(Identity::new(
            i,
            PublicKey::from_secret(&secret_key),
            SocketAddr::new("127.0.0.1".parse()?, 12000 + i as u16),
            1
        )))
    }

    // start network layer
    let mut network = UdpNetwork::new();
    let bind_to = SocketAddr::new(
        "0.0.0.0".parse().expect("Invalid IP address"),
        matches.value_of("port").expect("No port").parse()?,
    );

    // initialize agent
    let agent = Arc::new(HandelAgent::new(config, identities, network.sink()));

    let main_fut = network
        .connect(&bind_to, Arc::clone(&agent))
        .expect("Failed to initialize network")
        .join(agent.spawn()).map(|_| ());

    // run everything
    tokio::run(main_fut);

    Ok(())
}

fn main() {
    simple_logger::init_with_level(Level::Debug)
        .expect("Failed to initialize Logging");

    if let Err(e) = run_app() {
        error!("Error: {}", e);
    }
}
