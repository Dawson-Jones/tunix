use tunix::Configuration;
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut dev = Configuration::default()
        .address("192.168.108.1")
        .netmask("255.255.255.0")
        .up()
        .build_async()?;

    let mut buf = [0; 4096];
    loop {
        let n = dev.read(&mut buf[..]).await?;
        println!("packet received {n} size");
        for i in 0..n {
            print!("{:x} ", buf[i]);
        }
        println!();
    }
}
