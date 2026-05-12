use crate::configuration::Configuration;
use crate::error::*;
use std::net::Ipv4Addr;

pub trait Interface /*: Read + Write*/ {
    // type Queue: Read + Write;
    type Queue;

    fn configure(&mut self, config: &Configuration) -> Result<()> {
        if let Some(addr) = config.address {
            self.set_address(addr)?;
        }

        if let Some(addr) = config.destination {
            self.set_destination(addr)?;
        }

        if let Some(addr) = config.broadcast {
            self.set_broadcast(addr)?;
        }

        if let Some(addr) = config.netmask {
            self.set_netmask(addr)?;
        }

        if let Some(mtu) = config.mtu {
            self.set_mtu(mtu)?;
        }

        self.enable(config.enabled)?;

        Ok(())
    }

    fn name(&self) -> Result<String>;
    fn set_name(&mut self, name: &str) -> Result<()>;

    fn enable(&mut self, value: bool) -> Result<()>;
    fn flags(&self, flags: Option<i16>) -> Result<i16>;
    // fn set_enabled(&mut self, value: bool) -> Result<()>;

    fn address(&self) -> Result<Ipv4Addr>;
    fn set_address(&mut self, addr: Ipv4Addr) -> Result<()>;

    fn destination(&self) -> Result<Ipv4Addr>;
    fn set_destination(&mut self, addr: Ipv4Addr) -> Result<()>;

    fn broadcast(&self) -> Result<Ipv4Addr>;
    fn set_broadcast(&mut self, addr: Ipv4Addr) -> Result<()>;

    fn netmask(&self) -> Result<Ipv4Addr>;
    fn set_netmask(&mut self, addr: Ipv4Addr) -> Result<()>;

    fn mtu(&self) -> Result<i32>;
    fn set_mtu(&mut self, mtu: i32) -> Result<()>;

    fn queue(&mut self) -> &mut Self::Queue;
}
