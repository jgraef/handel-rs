use std::net::SocketAddr;
use std::io::{Write, ErrorKind, Cursor};

use tokio::net::{UdpSocket, UdpFramed};
use tokio::io::Error as IoError;
use tokio::codec::{Encoder, Decoder};
use bytes::{BytesMut, BufMut};
use futures::{Stream, Future, future};

use beserial::{Serialize, Deserialize, SerializingError, WriteBytesExt, ReadBytesExt, BigEndian};



#[derive(Debug, Default)]
pub struct Statistics {
    sent_count: usize,
    received_count: usize,
}

impl Statistics {
    pub fn sent(&mut self) {
        self.sent_count += 1;
        self.received_count += 1;
    }
}


pub struct Node {
}

impl Node {
    pub fn handle_messages(bind_to: &SocketAddr) -> impl Future {
        // set up UDP socket
        let socket = match UdpSocket::bind(bind_to) {
            Err(e) => return future::Either::A(future::err(e)),
            Ok(s) => s,
        };
        let framed = UdpFramed::new(socket, Codec::new());
        let (sink, stream) = framed.split();

        // consume messages
        future::Either::B(stream.for_each(|(message, sender_address)| {
            println!("Message: {:?}, from {}", message, sender_address);
            Ok(())
        }))
    }
}


#[derive(Clone, Debug, Serialize, Deserialize)]
struct Message {
    #[beserial(len_type(u8))]
    test: String,
}

struct Codec {}

impl Codec {
    pub fn new() -> Self {
        Codec {}
    }
}

impl Encoder for Codec {
    type Item = Message;
    type Error = IoError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // reserve enough space in buffer
        dst.reserve(item.serialized_size() + 2);

        let mut writer = dst.writer();

        // write length
        writer.write_u16::<BigEndian>(item.serialized_size() as u16)?;

        // write message
        item.serialize(&mut dst.writer())?;

        Ok(())
    }
}

impl Decoder for Codec {
    type Item = Message;
    type Error = IoError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // the frame size is unknown, therefore we have to read it first
        debug!("decode: remaining_mut={}", src.remaining_mut());

        // check if there is a u16 representing the frame size
        if src.remaining_mut() < 2 {
            // less than 2 bytes in buffer, thus we can't read the frame length
            return Ok(None)
        }

        // more than 2 bytes in buffer, read the frame length
        let mut raw_frame_size = src.split_to(2);
        let frame_size = raw_frame_size.as_ref().read_u16::<BigEndian>()? as usize;
        debug!("decode: frame_size={}", frame_size);

        // the frame size has already been read.

        // check if there is enough data in the buffer to read the whole message
        if src.remaining_mut() < frame_size {
            // not enough bytes in buffer to read the whole frame
            return Ok(None)
        }

        // enough bytes in buffer, deserialize the message
        let mut raw_message = src.split_to(frame_size);
        let message: Message = Deserialize::deserialize(&mut Cursor::new(raw_message.as_ref()))?;
        Ok(Some(message))
    }
}

