#[cfg(any(target_os = "linux", target_os = "macos"))]
use futures::{SinkExt, StreamExt};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use packet::{Builder, Packet, icmp, ip};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tunix::{Configuration, TunPacket};

// sudo route -q -n add -inet 192.168.108.0/24 -interface utun8

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dev = Configuration::default()
        .address("192.168.108.2")
        .netmask("255.255.255.0")
        .destination("192.168.108.1")
        .up()
        .build_async()?;

    let mut framed = dev.into_framed();

    while let Some(packet) = framed.next().await {
        let pkt = packet?;
        match ip::Packet::new(pkt.get_bytes()) {
            Ok(ip::Packet::V4(pkt)) => {
                if let Ok(icmp) = icmp::Packet::new(pkt.payload()) {
                    if let Ok(icmp) = icmp.echo() {
                        println!("{:?} - {:?}", icmp.sequence(), pkt.destination());

                        let reply = ip::v4::Builder::default()
                            .id(0x42)?
                            .ttl(64)?
                            .source(pkt.destination())?
                            .destination(pkt.source())?
                            .icmp()?
                            .echo()?
                            .reply()?
                            .identifier(icmp.identifier())?
                            .sequence(icmp.sequence())?
                            .payload(icmp.payload())?
                            .build()?;

                        framed.send(TunPacket::new(reply)).await?;
                    }
                }
            }
            Err(err) => println!("received an invalid packet: {:?}", err),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("async TUN examples are only supported on Linux and macOS");
}
