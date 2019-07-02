use failure::Fail;

use beserial::{Serialize, Deserialize, ReadBytesExt, WriteBytesExt, SerializingError};
use bls::bls12_381::{AggregateSignature, Signature};
use collections::bitset::BitSet;


#[derive(Clone, Debug, Fail)]
pub enum MultiSigError {
    #[fail(display = "Signatures are overlapping: {:?}", _0)]
    Overlapping(BitSet),
    #[fail(display = "Individual signature is already contained: {:?}", _0)]
    Contained(usize),
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiSignature {
    pub signature: AggregateSignature,
    pub signers: BitSet,
}

impl MultiSignature {
    pub fn from_aggregate(signature: AggregateSignature, signers: BitSet) -> MultiSignature {
        MultiSignature {
            signature,
            signers,
        }
    }

    pub fn from_individual(signature: &Signature, signer: usize) -> MultiSignature {
        let mut aggregate = AggregateSignature::new();
        let mut signers = BitSet::new();

        aggregate.aggregate(&signature);
        signers.insert(signer);

        MultiSignature {
            signature: aggregate,
            signers,
        }
    }

    pub fn len(&self) -> usize {
        self.signers.len()
    }

    pub fn add_multisig(&mut self, other: &MultiSignature) -> Result<(), MultiSigError> {
        // TODO: If we don't need the overlapping IDs for the error, we can use `intersection_size`
        let overlap = &self.signers & &other.signers;

        if overlap.is_empty() {
            self.signature.merge_into(&other.signature);
            self.signers = &self.signers & &other.signers;
            Ok(())
        }
        else {
            Err(MultiSigError::Overlapping(overlap))
        }
    }

    pub fn add_individual(&mut self, other: &Signature, peer_id: usize) -> Result<(), MultiSigError> {
        if self.signers.contains(peer_id) {
            Err(MultiSigError::Contained(peer_id))
        }
        else {
            self.signature.aggregate(other);
            self.signers.insert(peer_id);
            Ok(())
        }
    }

    // TODO: verify, etc.
}


/*
impl Serialize for MultiSignature {
    fn serialize<W: WriteBytesExt>(&self, writer: &mut W) -> Result<usize, SerializingError> {
        let mut size = 0;
        size += self.signature.serialize(writer)?;
        size += self.signers.serialize(writer)?;
        Ok(size)
    }

    fn serialized_size(&self) -> usize {
        self.signature.serialized_size() + self.signers.serialized_size()
    }
}

impl Deserialize for MultiSignature {
    fn deserialize<R: ReadBytesExt>(reader: &mut R) -> Result<Self, SerializingError> {
        let signature: AggregateSignature = Deserialize::deserialize(reader)?;
        let signers: BitSet = Deserialize::deserialize(reader)?;
        Ok(MultiSignature::from_aggregate(signature, signers))
    }
}
*/