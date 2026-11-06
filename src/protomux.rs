//! Bodies of the Protomux control messages (channel 0). Every Protomux frame is
//! `uint channel, uint type, body`; on channel 0 the types are
//! 0 = batch, 1 = open, 2 = reject, 3 = close. Framing and batching live in
//! `protomux-rs`.

use crate::{Bytes, Codec, Reader, Result, Writer, buffer_len, optional_buffer_len, uint_len};

pub const CONTROL_BATCH: u64 = 0;
pub const CONTROL_OPEN: u64 = 1;
pub const CONTROL_REJECT: u64 = 2;
pub const CONTROL_CLOSE: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    /// Sender's channel id, starting at 1.
    pub local_id: u64,
    pub protocol: String,
    pub id: Option<Bytes>,
    /// Raw remainder, decoded by the channel's handshake encoding.
    pub handshake: Bytes,
}

impl Codec for Open {
    fn encoded_len(&self) -> usize {
        uint_len(self.local_id)
            + buffer_len(self.protocol.len())
            + optional_buffer_len(self.id.as_deref())
            + self.handshake.len()
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.local_id);
        w.string(&self.protocol);
        w.optional_buffer(self.id.as_deref());
        w.raw(&self.handshake);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            local_id: r.uint()?,
            protocol: r.string()?,
            id: r.optional_buffer()?,
            handshake: r.raw(),
        })
    }
}

/// Body of `reject` (the remote's channel id) and `close` (the sender's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelRef {
    pub id: u64,
}

impl Codec for ChannelRef {
    fn encoded_len(&self) -> usize {
        uint_len(self.id)
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.id)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self { id: r.uint()? })
    }
}
