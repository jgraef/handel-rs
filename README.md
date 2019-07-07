
# handel-rs - Multi-Signature Aggregation in Large Byzantine Committees in Rust

This is a port of ConsenSys's Go implementation of the [Handel](https://github.com/ConsenSys/handel) protocol.

This code is still in development and is meant as a prototype to understand how the protocol works. It depends heavily on crates from [Nimiq](https://github.com/nimiq/core-rs) and will later be used for Nimiq's new PoS consensus algorithm [Albatross](https://arxiv.org/abs/1903.01589).

## Running

First clone [`core-rs`](https://github.com/nimiq/core-rs) and checkout the `albatross` branch:

```bash
git clone https://github.com/nimiq/core-rs.git
cd core-rs/
git checkout albatross
cd ..
```

Then clone `handel-rs`:

```bash
git clone https://github.com/jgraef/handel-rs.git
```

Make sure `core-rs` and `handel-rs` have the same parent directory. `handel-rs` uses dependencies from `core-rs` with a relative path to it.

```bash
cargo run -- -n NODES
```

will run a signature aggregation between `NODES` nodes. The nodes will eventually reach a valid signature, but will not terminate.
