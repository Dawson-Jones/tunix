#[cfg(any(target_os = "linux", target_os = "macos"))]
use futures::StreamExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use packet::ip::Packet;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tunix::Configuration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::main]
async fn main() {
    let dev = Configuration::default()
        .address("192.168.108.1")
        .netmask("255.255.255.0")
        .up()
        .build_async()
        .unwrap();

    let mut stream = dev.into_framed();
    while let Some(packet) = stream.next().await {
        match packet {
            Ok(pkt) => println!("pkt: {:#?}", Packet::unchecked(pkt.get_bytes())),
            Err(err) => panic!("Error: {:?}", err),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("async TUN examples are only supported on Linux and macOS");
}
