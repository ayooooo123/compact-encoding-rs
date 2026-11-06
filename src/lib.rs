#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub use bytes::Bytes;

pub mod hypercore;
pub mod protomux;

/// The JS library refuses arrays longer than this on decode.
pub const MAX_ARRAY_DECODE: u64 = 0x100000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    OutOfBounds,
    ArrayTooBig(u64),
    /// A value that the JS codec rejects, e.g. an unknown enum id.
    Invalid(&'static str, u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::OutOfBounds => f.write_str("Out of bounds"),
            Error::ArrayTooBig(n) => write!(f, "Array is too big: {n}"),
            Error::Invalid(what, n) => write!(f, "{what}: {n}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A type with one positional compact encoding.
pub trait Codec: Sized {
    fn encoded_len(&self) -> usize;
    fn encode(&self, w: &mut Writer);
    fn decode(r: &mut Reader) -> Result<Self>;
}

/// Encodes `v` into a buffer of exactly `v.encoded_len()` bytes.
pub fn encode<T: Codec>(v: &T) -> Bytes {
    let len = v.encoded_len();
    let mut w = Writer::with_capacity(len);
    v.encode(&mut w);
    debug_assert_eq!(w.len(), len, "encoded_len disagrees with encode");
    w.finish()
}

/// Decodes one `T` from the start of `buf`. Trailing bytes are ignored, as in JS.
pub fn decode<T: Codec>(buf: impl Into<Bytes>) -> Result<T> {
    T::decode(&mut Reader::new(buf.into()))
}

/// Encoded size of a compact uint.
pub const fn uint_len(n: u64) -> usize {
    if n <= 0xfc {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// Encoded size of a zig-zag compact int.
pub const fn int_len(n: i64) -> usize {
    uint_len(zigzag(n))
}

/// Encoded size of a length-prefixed byte buffer or string.
pub const fn buffer_len(len: usize) -> usize {
    uint_len(len as u64) + len
}

/// Encoded size of an optional buffer; `None` and empty both take one byte.
pub fn optional_buffer_len(b: Option<&[u8]>) -> usize {
    match b {
        Some(b) if !b.is_empty() => buffer_len(b.len()),
        _ => 1,
    }
}

/// Encoded size of an array of codec values.
pub fn array_len<T: Codec>(items: &[T]) -> usize {
    uint_len(items.len() as u64) + items.iter().map(Codec::encoded_len).sum::<usize>()
}

const fn zigzag(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

const fn unzigzag(n: u64) -> i64 {
    ((n >> 1) as i64) ^ -((n & 1) as i64)
}

const fn ip_family(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}

/// Appends encoded values to a growable buffer.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(n: usize) -> Self {
        Self {
            buf: Vec::with_capacity(n),
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn finish(self) -> Bytes {
        Bytes::from(self.buf)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn uint(&mut self, n: u64) {
        if n <= 0xfc {
            self.buf.push(n as u8);
        } else if n <= 0xffff {
            self.buf.push(0xfd);
            self.uint16(n as u16);
        } else if n <= 0xffff_ffff {
            self.buf.push(0xfe);
            self.uint32(n as u32);
        } else {
            self.buf.push(0xff);
            self.uint64(n);
        }
    }

    pub fn int(&mut self, n: i64) {
        self.uint(zigzag(n))
    }

    pub fn uint8(&mut self, n: u8) {
        self.buf.push(n)
    }

    pub fn uint16(&mut self, n: u16) {
        self.buf.extend_from_slice(&n.to_le_bytes())
    }

    pub fn uint24(&mut self, n: u32) {
        self.buf.extend_from_slice(&n.to_le_bytes()[..3])
    }

    pub fn uint32(&mut self, n: u32) {
        self.buf.extend_from_slice(&n.to_le_bytes())
    }

    pub fn uint32be(&mut self, n: u32) {
        self.buf.extend_from_slice(&n.to_be_bytes())
    }

    pub fn uint40(&mut self, n: u64) {
        self.buf.extend_from_slice(&n.to_le_bytes()[..5])
    }

    pub fn uint48(&mut self, n: u64) {
        self.buf.extend_from_slice(&n.to_le_bytes()[..6])
    }

    pub fn uint56(&mut self, n: u64) {
        self.buf.extend_from_slice(&n.to_le_bytes()[..7])
    }

    pub fn uint64(&mut self, n: u64) {
        self.buf.extend_from_slice(&n.to_le_bytes())
    }

    pub fn uint64be(&mut self, n: u64) {
        self.buf.extend_from_slice(&n.to_be_bytes())
    }

    pub fn int8(&mut self, n: i8) {
        self.uint8(zigzag(n as i64) as u8)
    }

    pub fn int16(&mut self, n: i16) {
        self.uint16(zigzag(n as i64) as u16)
    }

    pub fn int24(&mut self, n: i32) {
        self.uint24(zigzag(n as i64) as u32)
    }

    pub fn int32(&mut self, n: i32) {
        self.uint32(zigzag(n as i64) as u32)
    }

    pub fn int40(&mut self, n: i64) {
        self.uint40(zigzag(n))
    }

    pub fn int48(&mut self, n: i64) {
        self.uint48(zigzag(n))
    }

    pub fn int56(&mut self, n: i64) {
        self.uint56(zigzag(n))
    }

    pub fn int64(&mut self, n: i64) {
        self.uint64(zigzag(n))
    }

    pub fn float32(&mut self, n: f32) {
        self.buf.extend_from_slice(&n.to_le_bytes())
    }

    pub fn float64(&mut self, n: f64) {
        self.buf.extend_from_slice(&n.to_le_bytes())
    }

    pub fn bool(&mut self, b: bool) {
        self.buf.push(b as u8)
    }

    /// Length-prefixed bytes (`c.buffer`, `c.uint8array`).
    pub fn buffer(&mut self, b: &[u8]) {
        self.uint(b.len() as u64);
        self.buf.extend_from_slice(b)
    }

    /// `c.optionalBuffer`: `None` and an empty buffer both encode as `0`.
    pub fn optional_buffer(&mut self, b: Option<&[u8]>) {
        match b {
            Some(b) if !b.is_empty() => self.buffer(b),
            _ => self.buf.push(0),
        }
    }

    /// Bytes with no length prefix (`c.raw`, `c.fixed(n)`).
    pub fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b)
    }

    pub fn string(&mut self, s: &str) {
        self.buffer(s.as_bytes())
    }

    pub fn uint32array(&mut self, a: &[u32]) {
        self.uint(a.len() as u64);
        for n in a {
            self.uint32(*n)
        }
    }

    pub fn bitarray(&mut self, bits: &[bool]) {
        self.uint(bits.len() as u64);
        for chunk in bits.chunks(8) {
            let byte = chunk
                .iter()
                .enumerate()
                .fold(0u8, |b, (j, &bit)| b | ((bit as u8) << j));
            self.buf.push(byte)
        }
    }

    pub fn array<T: Codec>(&mut self, items: &[T]) {
        self.uint(items.len() as u64);
        for item in items {
            item.encode(self)
        }
    }

    /// `c.frame(enc)`: the value prefixed by its encoded length.
    pub fn frame<T: Codec>(&mut self, v: &T) {
        self.uint(v.encoded_len() as u64);
        v.encode(self)
    }

    pub fn ipv4(&mut self, ip: &Ipv4Addr) {
        self.raw(&ip.octets())
    }

    pub fn ipv6(&mut self, ip: &Ipv6Addr) {
        self.raw(&ip.octets())
    }

    /// `c.ip`: a family byte (4 or 6) then the address.
    pub fn ip(&mut self, ip: &IpAddr) {
        self.uint8(ip_family(ip));
        match ip {
            IpAddr::V4(a) => self.ipv4(a),
            IpAddr::V6(a) => self.ipv6(a),
        }
    }

    /// `c.ipAddress`: `c.ip` then a uint16 port.
    pub fn ip_address(&mut self, a: &SocketAddr) {
        self.ip(&a.ip());
        self.uint16(a.port())
    }

    /// `c.ipv4Address`: four address bytes then a uint16 port.
    pub fn ipv4_address(&mut self, a: &SocketAddrV4) {
        self.ipv4(a.ip());
        self.uint16(a.port())
    }

    /// `c.ipv6Address`: sixteen address bytes then a uint16 port.
    pub fn ipv6_address(&mut self, a: &SocketAddrV6) {
        self.ipv6(a.ip());
        self.uint16(a.port())
    }
}

/// Reads encoded values from a shared buffer.
#[derive(Debug, Clone)]
pub struct Reader {
    buf: Bytes,
    start: usize,
    end: usize,
}

impl Reader {
    pub fn new(buf: Bytes) -> Self {
        let end = buf.len();
        Self { buf, start: 0, end }
    }

    pub fn remaining(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Byte offset of the cursor within the original buffer.
    pub fn position(&self) -> usize {
        self.start
    }

    /// Steps the cursor back `n` bytes (JS `state.start -= n`), e.g. to
    /// re-read a version byte as flags.
    pub fn unread(&mut self, n: usize) -> Result<()> {
        if n > self.start {
            return Err(Error::OutOfBounds);
        }
        self.start -= n;
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.remaining() < n {
            return Err(Error::OutOfBounds);
        }
        let s = self.start;
        self.start += n;
        Ok(&self.buf[s..s + n])
    }

    fn take_bytes(&mut self, n: usize) -> Result<Bytes> {
        if self.remaining() < n {
            return Err(Error::OutOfBounds);
        }
        let s = self.start;
        self.start += n;
        Ok(self.buf.slice(s..s + n))
    }

    fn le<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn le_u64(&mut self, n: usize) -> Result<u64> {
        let mut out = [0u8; 8];
        out[..n].copy_from_slice(self.take(n)?);
        Ok(u64::from_le_bytes(out))
    }

    fn len_prefix(&mut self) -> Result<usize> {
        let n = self.uint()?;
        if n > self.remaining() as u64 {
            return Err(Error::OutOfBounds);
        }
        Ok(n as usize)
    }

    /// Like JS, non-minimal prefixes (e.g. `fd 05 00`) are accepted.
    pub fn uint(&mut self) -> Result<u64> {
        match self.uint8()? {
            a @ 0..=0xfc => Ok(a as u64),
            0xfd => self.uint16().map(u64::from),
            0xfe => self.uint32().map(u64::from),
            _ => self.uint64(),
        }
    }

    pub fn int(&mut self) -> Result<i64> {
        self.uint().map(unzigzag)
    }

    pub fn uint8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn uint16(&mut self) -> Result<u16> {
        self.le().map(u16::from_le_bytes)
    }

    pub fn uint24(&mut self) -> Result<u32> {
        self.le_u64(3).map(|n| n as u32)
    }

    pub fn uint32(&mut self) -> Result<u32> {
        self.le().map(u32::from_le_bytes)
    }

    pub fn uint32be(&mut self) -> Result<u32> {
        self.le().map(u32::from_be_bytes)
    }

    pub fn uint40(&mut self) -> Result<u64> {
        self.le_u64(5)
    }

    pub fn uint48(&mut self) -> Result<u64> {
        self.le_u64(6)
    }

    pub fn uint56(&mut self) -> Result<u64> {
        self.le_u64(7)
    }

    pub fn uint64(&mut self) -> Result<u64> {
        self.le().map(u64::from_le_bytes)
    }

    pub fn uint64be(&mut self) -> Result<u64> {
        self.le().map(u64::from_be_bytes)
    }

    pub fn int8(&mut self) -> Result<i8> {
        self.uint8().map(|n| unzigzag(n as u64) as i8)
    }

    pub fn int16(&mut self) -> Result<i16> {
        self.uint16().map(|n| unzigzag(n as u64) as i16)
    }

    pub fn int24(&mut self) -> Result<i32> {
        self.uint24().map(|n| unzigzag(n as u64) as i32)
    }

    pub fn int32(&mut self) -> Result<i32> {
        self.uint32().map(|n| unzigzag(n as u64) as i32)
    }

    pub fn int40(&mut self) -> Result<i64> {
        self.uint40().map(unzigzag)
    }

    pub fn int48(&mut self) -> Result<i64> {
        self.uint48().map(unzigzag)
    }

    pub fn int56(&mut self) -> Result<i64> {
        self.uint56().map(unzigzag)
    }

    pub fn int64(&mut self) -> Result<i64> {
        self.uint64().map(unzigzag)
    }

    pub fn float32(&mut self) -> Result<f32> {
        self.le().map(f32::from_le_bytes)
    }

    pub fn float64(&mut self) -> Result<f64> {
        self.le().map(f64::from_le_bytes)
    }

    /// JS treats any byte other than `1` as false.
    pub fn bool(&mut self) -> Result<bool> {
        self.uint8().map(|b| b == 1)
    }

    pub fn buffer(&mut self) -> Result<Bytes> {
        let n = self.len_prefix()?;
        self.take_bytes(n)
    }

    /// `c.optionalBuffer`: a zero length decodes as `None`.
    pub fn optional_buffer(&mut self) -> Result<Option<Bytes>> {
        let b = self.buffer()?;
        Ok((!b.is_empty()).then_some(b))
    }

    /// `c.raw`: everything up to the end of the current frame.
    pub fn raw(&mut self) -> Bytes {
        let b = self.buf.slice(self.start..self.end);
        self.start = self.end;
        b
    }

    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.le()
    }

    pub fn fixed_bytes(&mut self, n: usize) -> Result<Bytes> {
        self.take_bytes(n)
    }

    /// Invalid UTF-8 becomes U+FFFD, as with the JS decoder.
    pub fn string(&mut self) -> Result<String> {
        let n = self.len_prefix()?;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    pub fn uint32array(&mut self) -> Result<Vec<u32>> {
        let n = self.uint()?;
        if n.saturating_mul(4) > self.remaining() as u64 {
            return Err(Error::OutOfBounds);
        }
        (0..n).map(|_| self.uint32()).collect()
    }

    pub fn bitarray(&mut self) -> Result<Vec<bool>> {
        let n = self.uint()?;
        if n.div_ceil(8) > self.remaining() as u64 {
            return Err(Error::OutOfBounds);
        }
        let bytes = self.take(n.div_ceil(8) as usize)?;
        Ok((0..n as usize)
            .map(|i| bytes[i / 8] & (1 << (i % 8)) != 0)
            .collect())
    }

    pub fn array<T: Codec>(&mut self) -> Result<Vec<T>> {
        let n = self.uint()?;
        if n > MAX_ARRAY_DECODE {
            return Err(Error::ArrayTooBig(n));
        }
        // Each element takes at least one byte, which bounds the allocation.
        let mut out = Vec::with_capacity((n as usize).min(self.remaining()));
        for _ in 0..n {
            out.push(T::decode(self)?)
        }
        Ok(out)
    }

    /// `c.frame(enc)`: decodes one value inside a length-prefixed window and
    /// skips whatever the value leaves unread.
    pub fn frame<T: Codec>(&mut self) -> Result<T> {
        let n = self.len_prefix()?;
        let end = self.end;
        self.end = self.start + n;
        let v = T::decode(self);
        self.start = self.end;
        self.end = end;
        v
    }

    pub fn ipv4(&mut self) -> Result<Ipv4Addr> {
        self.le::<4>().map(Ipv4Addr::from)
    }

    pub fn ipv6(&mut self) -> Result<Ipv6Addr> {
        self.le::<16>().map(Ipv6Addr::from)
    }

    /// JS reads any family other than 4 as IPv6.
    pub fn ip(&mut self) -> Result<IpAddr> {
        Ok(match self.uint8()? {
            4 => IpAddr::V4(self.ipv4()?),
            _ => IpAddr::V6(self.ipv6()?),
        })
    }

    pub fn ip_address(&mut self) -> Result<SocketAddr> {
        let ip = self.ip()?;
        Ok(SocketAddr::new(ip, self.uint16()?))
    }

    pub fn ipv4_address(&mut self) -> Result<SocketAddrV4> {
        let ip = self.ipv4()?;
        Ok(SocketAddrV4::new(ip, self.uint16()?))
    }

    pub fn ipv6_address(&mut self) -> Result<SocketAddrV6> {
        let ip = self.ipv6()?;
        Ok(SocketAddrV6::new(ip, self.uint16()?, 0, 0))
    }
}

/// `c.uint`.
impl Codec for u64 {
    fn encoded_len(&self) -> usize {
        uint_len(*self)
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(*self)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        r.uint()
    }
}

/// `c.bool`.
impl Codec for bool {
    fn encoded_len(&self) -> usize {
        1
    }
    fn encode(&self, w: &mut Writer) {
        w.bool(*self)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        r.bool()
    }
}

/// `c.string` (UTF-8).
impl Codec for String {
    fn encoded_len(&self) -> usize {
        buffer_len(self.len())
    }
    fn encode(&self, w: &mut Writer) {
        w.string(self)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        r.string()
    }
}

/// `c.buffer`.
impl Codec for Bytes {
    fn encoded_len(&self) -> usize {
        buffer_len(self.len())
    }
    fn encode(&self, w: &mut Writer) {
        w.buffer(self)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        r.buffer()
    }
}

/// `c.fixed(N)`.
impl<const N: usize> Codec for [u8; N] {
    fn encoded_len(&self) -> usize {
        N
    }
    fn encode(&self, w: &mut Writer) {
        w.raw(self)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        r.fixed()
    }
}

/// `c.array(enc)`.
impl<T: Codec> Codec for Vec<T> {
    fn encoded_len(&self) -> usize {
        array_len(self)
    }
    fn encode(&self, w: &mut Writer) {
        w.array(self)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        r.array()
    }
}

#[cfg(test)]
mod tests;
