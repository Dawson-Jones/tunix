mod configuration;
pub use configuration::Configuration;

mod address;
mod error;
pub use error::{Error, Result};
pub mod interface;

mod platform;
pub use platform::tun;

#[cfg(all(
    feature = "async",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod r#async {
    pub mod codec;
    pub mod tun;
}
#[cfg(all(
    feature = "async",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub use r#async::{
    codec::PacketProtocol, codec::TunPacket, codec::TunPacketCodec, codec::infer_proto,
    tun::AsyncTun,
};
