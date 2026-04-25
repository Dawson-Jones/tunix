use tunix::Configuration;
use futures::StreamExt;
use packet::ip::Packet;

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
