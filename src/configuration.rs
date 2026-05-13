use std::net::Ipv4Addr;

#[cfg(unix)]
use std::os::unix::io::RawFd;

use crate::address::IntoIpv4Addr;
use crate::error::{Error, Result};
use crate::tun::{Tun, TunConf};
#[cfg(all(feature = "async", any(target_os = "linux", target_os = "macos")))]
use crate::AsyncTun;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Layer {
    L2,
    #[default]
    L3,
}

#[derive(Debug, Default, Clone)]
pub struct Configuration {
    pub(crate) name: Option<String>,
    pub(crate) platform: TunConf,

    pub(crate) address: Option<Ipv4Addr>,
    pub(crate) destination: Option<Ipv4Addr>,
    pub(crate) broadcast: Option<Ipv4Addr>,
    pub(crate) netmask: Option<Ipv4Addr>,
    // Keep invalid address input sticky so a later setter call cannot silently hide it.
    pub(crate) invalid_address: bool,
    pub(crate) mtu: Option<i32>,
    // Set the interface to be enabled once crated
    pub(crate) enabled: bool,
    pub(crate) layer: Layer,
    pub(crate) queues: Option<usize>,
    #[cfg(unix)]
    pub(crate) raw_fd: Option<RawFd>,
}

impl Configuration {
    pub fn platform<F: FnOnce(&mut TunConf)>(&mut self, f: F) -> &mut Self {
        f(&mut self.platform);
        self
    }

    pub fn name<S: AsRef<str>>(&mut self, name: S) -> &mut Self {
        self.name = Some(name.as_ref().into());
        self
    }

    pub fn address<A: IntoIpv4Addr>(&mut self, value: A) -> &mut Self {
        match value.into_ipv4() {
            Ok(addr) => self.address = Some(addr),
            Err(_) => self.invalid_address = true,
        }

        self
    }

    pub fn destination<A: IntoIpv4Addr>(&mut self, value: A) -> &mut Self {
        match value.into_ipv4() {
            Ok(addr) => self.destination = Some(addr),
            Err(_) => self.invalid_address = true,
        }

        self
    }

    pub fn broadcast<A: IntoIpv4Addr>(&mut self, value: A) -> &mut Self {
        match value.into_ipv4() {
            Ok(addr) => self.broadcast = Some(addr),
            Err(_) => self.invalid_address = true,
        }

        self
    }

    pub fn netmask<A: IntoIpv4Addr>(&mut self, value: A) -> &mut Self {
        match value.into_ipv4() {
            Ok(addr) => self.netmask = Some(addr),
            Err(_) => self.invalid_address = true,
        }

        self
    }

    pub fn mtu(&mut self, value: i32) -> &mut Self {
        self.mtu = Some(value);
        self
    }

    pub fn up(&mut self) -> &mut Self {
        self.enabled = true;
        self
    }

    pub fn down(&mut self) -> &mut Self {
        self.enabled = false;
        self
    }

    pub fn layer(&mut self, layer: Layer) -> &mut Self {
        self.layer = layer;
        self
    }

    pub fn queues(&mut self, queues: usize) -> &mut Self {
        self.queues = Some(queues);
        self
    }

    #[cfg(unix)]
    pub fn raw_fd(&mut self, fd: RawFd) -> &mut Self {
        self.raw_fd = Some(fd);
        self
    }

    pub fn build(&self) -> Result<Tun> {
        self.ensure_valid()?;

        match self.queues {
            Some(n) if n > 1 => Err(Error::InvalidConfig),
            _ => Tun::new(self),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn build_multi_queue(&self) -> Result<Vec<Tun>> {
        self.ensure_valid()?;

        Tun::new_multi_queue(self)
    }

    #[cfg(all(feature = "async", any(target_os = "linux", target_os = "macos")))]
    pub fn build_async(&self) -> Result<AsyncTun> {
        self.ensure_valid()?;

        AsyncTun::new(Tun::new(self)?)
    }

    #[cfg(all(feature = "async", target_os = "linux"))]
    pub fn build_async_multi_queue(&self) -> Result<Vec<AsyncTun>> {
        self.ensure_valid()?;

        AsyncTun::new_multi_queue(Tun::new_multi_queue(self)?)
    }

    fn ensure_valid(&self) -> Result<()> {
        if self.invalid_address {
            return Err(Error::InvalidAddress);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Configuration;
    use crate::error::Error;

    #[test]
    fn invalid_address_is_reported_by_build() {
        let mut config = Configuration::default();
        let result = config.address("not an ip").build();

        assert!(matches!(result, Err(Error::InvalidAddress)));
    }
}
