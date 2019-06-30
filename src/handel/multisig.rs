use beserial::{Serialize, Deserialize, ReadBytesExt, WriteBytesExt, SerializingError};
use bls::bls12_381::AggregateSignature;
use collections::bitset::BitSet;


#[derive(Clone, Debug)]
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
        Ok(MultiSignature::from(signature, signers))
    }
}