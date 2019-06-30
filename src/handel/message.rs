use beserial::{Serialize, Deserialize};
use bls::bls12_381::Signature;

use crate::handel::MultiSignature;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub origin: u16,
    pub level: u8,
    pub multisig: MultiSignature,
    pub individual: Option<Signature>,
}
