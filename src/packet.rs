use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

pub struct RconPacket {
    pub id: i32,
    pub ty: i32,
    pub body: bytes::Bytes,
}

impl RconPacket {
    pub fn auth(id: i32, password: impl Into<Bytes>) -> Self {
        Self {
            id,
            ty: SERVERDATA_AUTH,
            body: password.into(),
        }
    }
    pub fn command(id: i32, command: impl Into<Bytes>) -> Self {
        Self {
            id,
            ty: SERVERDATA_EXECCOMMAND,
            body: command.into(),
        }
    }
}
pub const SERVERDATA_AUTH: i32 = 3;
pub const SERVERDATA_AUTH_RESPONSE: i32 = 2;
pub const SERVERDATA_EXECCOMMAND: i32 = 2;
pub const SERVERDATA_RESPONSE_VALUE: i32 = 0;
pub const AUTH_FAIL: i32 = -1;
pub(crate) const BODY_TERMINATE_BYTE: u8 = 0x00;
pub(crate) const MAX_PACKET_SIZE: usize = 4096;
pub(crate) const MIN_PACKET_SIZE: usize = 10;
pub(crate) const MARGIN: usize = 9;
#[derive(Debug, Default)]
pub struct RconPacketCodec;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("Io error {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid packet size {0}")]
    InvalidPacketSize(usize),
    #[error("Expect terminator 0x00")]
    ExpectTerminator,
}

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("Io error {0}")]
    Io(#[from] std::io::Error),
    #[error("Body too large: {0}")]
    BodyTooLarge(usize),
    #[error("Body is empty")]
    BodyIsEmpty,
}

impl Decoder for RconPacketCodec {
    type Item = RconPacket;

    type Error = DecodeError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, DecodeError> {
        let Ok(size) = buf.try_get_i32_le() else {
            return Ok(None);
        };
        let size = size as usize;
        // check size
        let buf_size = buf.len();
        if buf_size < size {
            return Ok(None);
        }
        if !(MIN_PACKET_SIZE..=MAX_PACKET_SIZE).contains(&size) {
            return Err(DecodeError::InvalidPacketSize(size));
        }
        if buf_size < size {
            return Ok(None);
        }
        let id = buf.get_i32_le();
        let ty = buf.get_i32_le();
        let body_size = size - MARGIN;
        let body = buf.split_to(body_size).freeze();
        // expect terminate
        let terminate = buf.get_u8();
        if terminate != BODY_TERMINATE_BYTE {
            return Err(DecodeError::ExpectTerminator);
        }
        Ok(Some(RconPacket { id, ty, body }))
    }
}

impl Encoder<RconPacket> for RconPacketCodec {
    type Error = EncodeError;

    fn encode(&mut self, item: RconPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let size = item.body.len() + MARGIN;
        if size < MIN_PACKET_SIZE {
            return Err(EncodeError::BodyIsEmpty);
        } else if size > MAX_PACKET_SIZE {
            return Err(EncodeError::BodyTooLarge(size));
        }
        dst.put_i32_le(size as i32);
        dst.put_i32_le(item.id);
        dst.put_i32_le(item.ty);
        dst.put(item.body);
        dst.put_u8(BODY_TERMINATE_BYTE);
        Ok(())
    }
}
