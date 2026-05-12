#[cfg(target_os = "linux")]
mod linux {
    mod sys;
    pub mod tun;
}
#[cfg(target_os = "linux")]
pub use linux::tun;

#[cfg(target_os = "macos")]
mod macos {
    mod sys;
    pub mod tun;
}
#[cfg(target_os = "macos")]
pub use macos::tun;

#[cfg(unix)]
pub(crate) mod posix {
    pub mod fd;
    pub mod name;
    pub mod sys;
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use crate::{configuration::Configuration, interface::Interface};

    #[test]
    #[cfg(target_os = "linux")]
    fn create_for_linux() {
        let mut config = Configuration::default();

        let mut dev = config
            .name("tun0")
            .address("192.168.50.1")
            .netmask("255.255.255.0")
            .mtu(1400)
            .build()
            .unwrap();

        assert_eq!("tun0", dev.name().unwrap());

        dev.set_name("tun9").unwrap();
        assert_eq!("tun9", dev.name().unwrap());

        // dev.enable(true).unwrap();

        assert_eq!(
            "192.168.50.1".parse::<Ipv4Addr>().unwrap(),
            dev.address().unwrap()
        );

        assert_eq!(
            "255.255.255.0".parse::<Ipv4Addr>().unwrap(),
            dev.netmask().unwrap()
        );

        assert_eq!(1400, dev.mtu().unwrap());
    }

    #[test]
    fn create() {
        let mut config = Configuration::default();

        let dev = config
            .name("utun6")
            .address("192.168.50.1")
            .netmask("255.255.255.0")
            .mtu(1400)
            .up()
            .build()
            .unwrap();

        assert_eq!("utun6", dev.name().unwrap());

        assert_eq!(
            "192.168.50.1".parse::<Ipv4Addr>().unwrap(),
            dev.address().unwrap()
        );

        assert_eq!(
            "255.255.255.0".parse::<Ipv4Addr>().unwrap(),
            dev.netmask().unwrap()
        );

        assert_eq!(1400, dev.mtu().unwrap());
    }
}
