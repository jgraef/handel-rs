use collections::bitset::BitSet;
use beserial::{Serialize, Deserialize};
use bls::bls12_381::{Signature, AggregateSignature};



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    #[beserial(len_type(u8))]
    test: String,
}
