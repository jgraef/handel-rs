use std::net::SocketAddr;
use std::io::{Cursor, ErrorKind};
use std::sync::Arc;

use tokio::net::{UdpSocket, UdpFramed};
use tokio::io::Error as IoError;
use tokio::codec::{Encoder, Decoder};
use tokio::executor::Spawn;
use bytes::{BytesMut, BufMut};
use futures::{Stream, Future, StartSend, Sink, future, IntoFuture, Join};
use futures::stream::{SplitSink, SplitStream, ForEach};
use futures::sync::mpsc::{unbounded, UnboundedSender, UnboundedReceiver};
use parking_lot::RwLock;
use failure::Error;

use beserial::{Serialize, Deserialize, WriteBytesExt, ReadBytesExt, BigEndian};

use crate::handel::Message;
use futures::future::FutureResult;


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
    fn on_message(&self, message: Message, sender_address: SocketAddr) -> Box<dyn Future<Item=(), Error=IoError> + Send>;
}


pub type HandelSink = UnboundedSender<(Message, SocketAddr)>;
pub type HandelStream = SplitStream<UdpFramed<Codec>>;


pub struct UdpNetwork {
    pub statistics: Arc<RwLock<Statistics>>,
    sender: UnboundedSender<(Message, SocketAddr)>,
    receiver: Option<UnboundedReceiver<(Message, SocketAddr)>>,
}

type UdpNetworkFuture = Box<dyn Future<Item=(), Error=()> + Send>;

impl UdpNetwork {
    pub fn new() -> Self {
        let (sender, receiver) = unbounded::<(Message, SocketAddr)>();
        Self {
            statistics: Arc::new(RwLock::new(Statistics::default())),
            sender,
            receiver: Some(receiver),
        }
    }

    pub fn connect<H: Handler + Send + 'static>(&mut self, bind_to: &SocketAddr, handler: H) -> Result<UdpNetworkFuture, IoError> {
        // set up UDP socket
        let socket = UdpSocket::bind(bind_to)?;
        let framed = UdpFramed::new(socket, Codec::new(Arc::clone(&self.statistics)));
        let (sink, stream) = framed.split();

        if let Some(receiver) = self.receiver.take() {
            Ok(Box::new(future::lazy(move || {
                let buf_fut = sink.send_all(receiver
                    .map_err(|_| {
                        error!("Send buffer returned an error");
                        IoError::from(ErrorKind::ConnectionReset)
                    })
                );

                let buf_spawn = tokio::spawn(buf_fut.map(|(sink, source)| {
                    warn!("Buffer thread finished");
                }).map_err(|e| {
                    error!("Send buffer failed: {}", e);
                }));

                let recv_spawn = tokio::spawn(stream.for_each(move |(message, sender_address)| {
                    //debug!("Received from {}: {:?}", sender_address, message);
                    handler.on_message(message, sender_address)
                }).or_else(|e| {
                    error!("Receive stream error: {}", e);
                    future::ok(())
                }));

                buf_spawn.into_future()
                    .join(recv_spawn.into_future())
                    .map(|_| ()) // join returns ((), ()), so map it to ()
            })))
        }
        else {
            Err(IoError::from(ErrorKind::AlreadyExists))
        }
    }

    pub fn sink(&self) -> HandelSink {
        self.sender.clone()
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
        //info!("Sending message: {:?}", item);

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
        // check if there is a u16 representing the frame size
        if src.remaining_mut() < 2 {
            // less than 2 bytes in buffer, thus we can't read the frame length
            return Ok(None)
        }

        // more than 2 bytes in buffer, read the frame length
        let raw_frame_size = src.split_to(2);
        let frame_size = raw_frame_size.as_ref().read_u16::<BigEndian>()? as usize;

        if frame_size > 1024 {
            return Err(IoError::from(ErrorKind::InvalidData))
        }

        // check if there is enough data in the buffer to read the whole message
        if src.remaining_mut() < frame_size {
            // not enough bytes in buffer to read the whole frame
            return Ok(None)
        }

        // enough bytes in buffer, deserialize the message
        let raw_message = src.split_to(frame_size);
        let decoded = Deserialize::deserialize(&mut Cursor::new(raw_message.as_ref()));
        match decoded {
            Ok(message) => {
                // statistics
                self.statistics.write().received();
                Ok(Some(message))
            },
            Err(e) => {
                warn!("Failed deserializing message: {:?}", e);
                Err(e.into())
            }
        }
    }
}

