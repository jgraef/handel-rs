use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

use beserial::{Serialize, Deserialize, ReadBytesExt, WriteBytesExt, SerializingError, BigEndian};
use bls::bls12_381::PublicKey;


#[derive(Clone, Debug)]
pub struct Identity {
    pub id: usize,
    pub public_key: PublicKey,
    pub address: SocketAddr,
}

impl Identity {
    pub fn new(id: usize, public_key: PublicKey, address: SocketAddr) -> Identity {
        Identity {
            id,
            public_key,
            address
        }
    }
}

impl Serialize for Identity {
    fn serialize<W: WriteBytesExt>(&self, writer: &mut W) -> Result<usize, SerializingError> {
        let mut size = 2;
        writer.write_u16::<BigEndian>(self.id as u16)?;
        size += Serialize::serialize(&self.public_key, writer)?;
        size += serialize_socket_addr(&self.address, writer)?;
        Ok(size)
    }

    fn serialized_size(&self) -> usize {
        2 + self.public_key.serialized_size() + serialized_size_socket_addr(&self.address)
    }
}

impl Deserialize for Identity {
    fn deserialize<R: ReadBytesExt>(reader: &mut R) -> Result<Self, SerializingError> {
        let id = reader.read_u16::<BigEndian>()? as usize;
        let public_key: PublicKey = Deserialize::deserialize(reader)?;
        let address = deserialize_socket_addr(reader)?;
        Ok(Identity {
            id,
            public_key,
            address
        })
    }
}

fn serialize_socket_addr<W: WriteBytesExt>(address: &SocketAddr, writer: &mut W) -> Result<usize, SerializingError> {
    let mut size = 0;

    // serialize IP
    match address.ip() {
        IpAddr::V4(ref v4) => {
            writer.write_u8(4);
            writer.write(&v4.octets());
            size += 4;
        },
        IpAddr::V6(ref v6) => {
            writer.write_u8(6);
            writer.write(&v6.octets());
            size += 16
        },
    };

    // serialize port
    writer.write_u16::<BigEndian>(address.port())?;
    size += 2;

    Ok(size)
}

fn serialized_size_socket_addr(address: &SocketAddr) -> usize {
    //   1         ip address version
    // + 2         port
    // + 4 or 16   octects
    match address {
        SocketAddr::V4(_) => 7,
        SocketAddr::V6(_) => 19,
    }
}

fn deserialize_socket_addr<R: ReadBytesExt>(reader: &mut R) -> Result<SocketAddr, SerializingError> {
    let v = reader.read_u8()?;
    let ip = match v {
        4 => {
            let mut octects = [0u8; 4];
            reader.read_exact(&mut octects)?;
            IpAddr::V4(Ipv4Addr::from(octects))
        },
        6 => {
            let mut octects = [0u8; 16];
            reader.read_exact(&mut octects)?;
            IpAddr::V6(Ipv6Addr::from(octects))
        },
        _ => {
            return Err(SerializingError::InvalidEncoding)
        }
    };
    let port = reader.read_u16::<BigEndian>()?;

    Ok(SocketAddr::new(ip, port))
}
