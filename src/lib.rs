mod configuration;
pub use configuration::Configuration;

mod address;
mod error;
pub mod interface;

mod platform;
pub use platform::tun;

#[cfg(all(feature = "async", any(target_os = "linux", target_os = "macos")))]
mod r#async {
    pub mod codec;
    pub mod tun;
}
#[cfg(all(feature = "async", any(target_os = "linux", target_os = "macos")))]
pub use r#async::{
    codec::PacketProtocol, codec::TunPacket, codec::TunPacketCodec, codec::infer_proto,
    tun::AsyncTun,
};
