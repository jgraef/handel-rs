use std::net::SocketAddr;
use std::io::{Write, ErrorKind, Cursor};
use std::sync::Arc;
use std::marker::PhantomData;

use tokio::net::{UdpSocket, UdpFramed};
use tokio::io::Error as IoError;
use tokio::codec::{Encoder, Decoder};
use bytes::{BytesMut, BufMut};
use futures::{Stream, Future, future};
use futures::stream::{SplitSink, SplitStream, ForEach};
use parking_lot::RwLock;

use beserial::{Serialize, Deserialize, SerializingError, WriteBytesExt, ReadBytesExt, BigEndian};

use crate::handel::Message;



#[derive(Debug, Default)]
pub struct Statistics {
    received_count: usize,
    sent_count: usize,
}

impl Statistics {
    pub fn received(&mut self) {
        self.received_count += 1;
    }

    pub fn sent(&mut self) {
        self.sent_count += 1;
    }
}


pub trait Handler {
    fn on_message(&mut self, message: Message, sender_address: SocketAddr) -> Result<(), IoError>;
}


pub type Incoming = ForEach<
    SplitStream<UdpFramed<Codec>>,
    Box<dyn FnMut((Message, SocketAddr)) -> Result<(), IoError> + Send>,
    Result<(), IoError>
>;


pub struct UdpNetwork {
    pub statistics: Arc<RwLock<Statistics>>,
    pub sink: SplitSink<UdpFramed<Codec>>,
    pub incoming: Incoming,
}

impl UdpNetwork {
    pub fn new<H: Handler + Send + 'static>(bind_to: &SocketAddr, mut handler: H) -> Result<Self, IoError> {
        // set up UDP socket
        let socket = UdpSocket::bind(bind_to)?;
        let statistics = Arc::new(RwLock::new(Statistics::default()));
        let framed = UdpFramed::new(socket, Codec::new(Arc::clone(&statistics)));
        let (sink, stream) = framed.split();

        let incoming: Incoming = stream.for_each(Box::new(move |(message, sender_address)| {
            debug!("Message: {:?} from {}", message, sender_address);
            handler.on_message(message, sender_address);
            Ok(())
        }));

        Ok(Self {
            statistics,
            sink,
            incoming,
        })
    }
}

pub struct Codec {
    statistics: Arc<RwLock<Statistics>>,
}

impl Codec {
    pub fn new(statistics: Arc<RwLock<Statistics>>) -> Self {
        Codec {
            statistics,
        }
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

        // statistics
        self.statistics.write().sent();

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

        // statistics
        self.statistics.write().received();

        Ok(Some(message))
    }
}

