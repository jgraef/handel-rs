use bls::bls12_381::AggregateSignature;
use collections::bitset::BitSet;


pub struct MultiSignature {
    pub signature: AggregateSignature,
    pub signers: BitSet,
    pub num_signers: usize,
}

impl MultiSignature {
    pub fn from(signature: AggregateSignature, signers: BitSet) -> MultiSignature {
        let num_signers = signers.len();
        MultiSignature {
            signature,
            signers,
            num_signers,
        }
    }

    // TODO: verify
}
