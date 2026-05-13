#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::io::AsyncReadExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tunix::Configuration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("async TUN examples are only supported on Linux and macOS");
}
