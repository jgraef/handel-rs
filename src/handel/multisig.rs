use beserial::{Serialize, Deserialize, ReadBytesExt, WriteBytesExt, SerializingError};
use bls::bls12_381::{AggregateSignature, Signature};
use collections::bitset::BitSet;


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