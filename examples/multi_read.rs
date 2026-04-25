use tunix::Configuration;
use std::io::Read;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{io, thread};

    let tuns = Configuration::default()
        .address("10.0.0.9")
        .netmask("255.255.255.0")
        .queues(2)
        .destination("10.0.0.1")
        .platform(|tun_conf| {
            tun_conf.packet_information(true);
        })
        .up()
        .build_multi_queue()?;

    let mut threads: Vec<thread::JoinHandle<Result<(), io::Error>>> = Vec::new();
    for (number, mut tun) in tuns.into_iter().enumerate() {
        let t = thread::spawn(move || -> io::Result<()> {
            let mut buf = [0u8; 4096];
            loop {
                let n = tun.read(&mut buf)?;
                println!("thread: {}, read {} bytes", number, n);
                println!("thread: {}, {:?}", number, &buf[..n]);
            }
        });

        threads.push(t);
    }

    for t in threads {
        let _ = t.join().unwrap();
    }

    Ok(())
}
