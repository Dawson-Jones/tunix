use tunix::{TunPacketCodec, AsyncTun, Configuration, TunPacket};
use futures::{SinkExt, StreamExt};
use packet::{icmp, ip, Builder, Packet};
use tokio_util::codec::Framed;


async fn reply_ping(number: usize, mut framed: Framed<AsyncTun, TunPacketCodec>) -> Result<(), Box<dyn std::error::Error>>{
    while let Some(packet) = framed.next().await {
        let pkt = packet?;

        match ip::Packet::new(pkt.get_bytes()) {
            Ok(ip::Packet::V4(pkt)) => {
                if let Ok(icmp) = icmp::Packet::new(pkt.payload()) {
                    if let Ok(icmp) = icmp.echo() {
                        println!("mq: {}, {:?} - {:?}", number, icmp.sequence(), pkt.destination());

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let queues = Configuration::default()
        .address("192.168.108.2")
        .netmask("255.255.255.0")
        .destination("192.168.108.1")
        .queues(2)
        .up()
        .build_async_multi_queue()?;

    let mut conroutines = Vec::new();
    for (idx, dev) in queues.into_iter().enumerate() {
        let framed = dev.into_framed();

        let cr = tokio::spawn(async move {
            reply_ping(idx, framed).await.unwrap();
        });

        conroutines.push(cr);
    }

    println!("{} conroutines running...", conroutines.len());
    futures::future::join_all(conroutines).await;

    Ok(())
}
