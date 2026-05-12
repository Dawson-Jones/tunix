use byteorder::{NativeEndian, NetworkEndian, WriteBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone, Copy, Default)]
pub enum PacketProtocol {
    #[default]
    Ipv4,
    Ipv6,
    Other(u8),
}

/// Infer the IP protocol from the first byte. Empty input is reported as `Other(0)`.
pub fn infer_proto(pkt: &[u8]) -> PacketProtocol {
    // | version: 4bits | ihl: 4 bits | service: 8 bits | total length: 16 bits
    // | identification: 16 bits | flags: 3 bits, fragment offset: 13 bits
    // | time to live: 8 bits | protocol: 8 bits | header checksum: 16 bits
    // | source address: 32 bits
    // | destination address: 32 bits
    match pkt.first().map(|byte| byte >> 4) {
        Some(4) => PacketProtocol::Ipv4,
        Some(6) => PacketProtocol::Ipv6,
        Some(p) => PacketProtocol::Other(p),
        None => PacketProtocol::Other(0),
    }
}

impl PacketProtocol {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn into_pi_field(self) -> Result<u16, io::Error> {
        match self {
            PacketProtocol::Ipv4 => Ok(libc::PF_INET as u16),
            PacketProtocol::Ipv6 => Ok(libc::PF_INET6 as u16),
            PacketProtocol::Other(p) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("neither an Ipv4 nor Ipv6 packet: {p}"),
            )),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn into_pi_field(self) -> Result<u16, io::Error> {
        match self {
            PacketProtocol::Ipv4 => Ok(libc::ETH_P_IP as u16),
            PacketProtocol::Ipv6 => Ok(libc::ETH_P_IPV6 as u16),
            PacketProtocol::Other(p) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("neither an Ipv4 nor Ipv6 packet: {p}"),
            )),
        }
    }
}

pub struct TunPacket(PacketProtocol, Bytes);

impl TunPacket {
    pub fn new<T: Into<Bytes>>(pkt: T) -> Self {
        let pkt: Bytes = pkt.into();
        let proto = infer_proto(&pkt);
        Self(proto, pkt)
    }

    pub fn get_bytes(&self) -> &[u8] {
        &self.1
    }

    pub fn into_bytes(self) -> Bytes {
        self.1
    }
}

impl From<TunPacket> for Bytes {
    fn from(value: TunPacket) -> Self {
        value.1
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TunPacketCodec(bool, i32);

impl TunPacketCodec {
    pub fn new(pi: bool, mtu: i32) -> Self {
        Self(pi, mtu)
    }
}

/// impl [`Decoder`] and [`Encoder`] trait for TunPacketCodec
/// the [`Framed`] will implement the [`Stream`] trait
///
/// [`Decoder`]: tokio_util::codec::Decoder
/// [`Encoder`]: tokio_util::codec::Encoder
/// [`Framed`]: tokio_util::codec::Framed
/// [`Stream`]: futures::stream::Stream
impl Decoder for TunPacketCodec {
    type Item = TunPacket;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut pkt = buf.split_to(buf.len());

        // packet information
        if self.0 {
            if pkt.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet information header is shorter than 4 bytes",
                ));
            }

            // reserve enough space for next packet
            buf.reserve(self.1 as usize + 4);
            // ignore the first 4 bytes
            let _ = pkt.split_to(4);
        } else {
            buf.reserve(self.1 as usize);
        }

        if pkt.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet payload is empty",
            ));
        }

        let proto = infer_proto(pkt.as_ref());
        Ok(Some(TunPacket(proto, pkt.freeze())))
    }
}

impl Encoder<TunPacket> for TunPacketCodec {
    type Error = io::Error;

    fn encode(&mut self, item: TunPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(item.get_bytes().len() + 4);

        match item {
            TunPacket(proto, pkt) if self.0 => {
                let mut pi = Vec::<u8>::with_capacity(4);

                // flags is always 0
                pi.write_u16::<NativeEndian>(0)?;
                // write the protocol as network byte order
                pi.write_u16::<NetworkEndian>(proto.into_pi_field()?)?;

                dst.put_slice(&pi);
                dst.put(pkt);
            }
            TunPacket(_, pkt) => dst.put(pkt),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{PacketProtocol, TunPacketCodec, infer_proto};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    #[test]
    fn infer_proto_accepts_empty_packet() {
        assert!(matches!(infer_proto(&[]), PacketProtocol::Other(0)));
    }

    #[test]
    fn decoder_rejects_short_packet_information_header() {
        let mut codec = TunPacketCodec::new(true, 1500);
        let mut buf = BytesMut::from(&[0u8, 0, 8][..]);

        let result = codec.decode(&mut buf);

        assert!(matches!(
            result,
            Err(err) if err.kind() == std::io::ErrorKind::InvalidData
        ));
    }
}
