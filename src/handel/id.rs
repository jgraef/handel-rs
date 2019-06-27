use std::fmt::{Debug, Formatter, Error};
use std::io::Write;

use beserial::{Serialize, Deserialize, WriteBytesExt, ReadBytesExt, SerializingError};
use bls::bls12_381::PublicKey;

use hash::{Blake2bHash, Hash, Blake2bHasher, Hasher, HashOutput};


#[derive(Clone)]
pub struct NodeId([u8; Self::LENGTH]);

impl NodeId {
    const LENGTH: usize = 64;
}

impl Debug for NodeId {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        unimplemented!()
    }
}

impl From<PublicKey> for NodeId {
    fn from(pk: PublicKey) -> Self {
        let mut hasher = Blake2bHasher::new();
        hasher.write(pk.serialize_to_vec().as_slice()).unwrap();
        let mut id = [0u8; Self::LENGTH];
        id.copy_from_slice(hasher.finish().as_bytes());
        NodeId(id)
    }
}

impl Serialize for NodeId {
    fn serialize<W: WriteBytesExt>(&self, writer: &mut W) -> Result<usize, SerializingError> {
        writer.write(&self.0).map_err(SerializingError::from)
    }

    fn serialized_size(&self) -> usize {
        Self::LENGTH
    }
}

impl Deserialize for NodeId {
    fn deserialize<R: ReadBytesExt>(reader: &mut R) -> Result<Self, SerializingError> {
        let mut id = [0; Self::LENGTH];
        reader.read(&mut id)?;
        Ok(NodeId(id))
    }
}

impl PartialEq for NodeId {
    fn eq(&self, other: &Self) -> bool {
        self.0.iter().zip(other.0.iter())
            .all(|(a, b)| *a == *b)
    }
}

impl std::hash::Hash for NodeId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for a in self.0.iter() {
            state.write_u8(*a);
        }
    }
}

impl Eq for NodeId {}