use collections::bitset::BitSet;
use beserial::{Serialize, Deserialize};
use bls::bls12_381::{Signature, AggregateSignature};

use crate::handel::NodeId;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    level: u8,
    individual: Signature,
    aggregated: AggregateSignature,
    signers: BitSet,
    signer_idx: u16,
    sender_id: NodeId,
}
