use std::{
    ffi::OsString,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use crate::{
    configuration::{Configuration, Layer},
    error::{Error, Result},
    interface::Interface,
};
use wintun::{Adapter, MAX_RING_CAPACITY, Session, load_from_path};

use super::sys;

const TUNNEL_TYPE: &str = "tunix";

#[derive(Debug, Clone)]
pub struct TunConf {
    pub(crate) device_guid: Option<u128>,
    pub(crate) wintun_file: OsString,
    pub(crate) ring_capacity: u32,
}

impl Default for TunConf {
    fn default() -> Self {
        Self {
            device_guid: None,
            wintun_file: "wintun.dll".into(),
            ring_capacity: MAX_RING_CAPACITY,
        }
    }
}

impl TunConf {
    pub fn device_guid(&mut self, value: u128) -> &mut Self {
        self.device_guid = Some(value);
        self
    }

    pub fn wintun_file<S: Into<OsString>>(&mut self, value: S) -> &mut Self {
        self.wintun_file = value.into();
        self
    }

    pub fn ring_capacity(&mut self, value: u32) -> &mut Self {
        self.ring_capacity = value;
        self
    }
}

#[derive(Clone)]
pub struct Queue {
    session: Arc<Session>,
}

impl Queue {
    pub fn has_packet_information(&self) -> bool {
        false
    }

    fn read_by_ref(&self, buf: &mut [u8]) -> io::Result<usize> {
        let packet = self
            .session
            .receive_blocking()
            .map_err(|err| io::Error::new(io::ErrorKind::ConnectionAborted, err))?;
        let bytes = packet.bytes();

        if bytes.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer is smaller than the received packet",
            ));
        }

        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }

    fn write_by_ref(&self, buf: &[u8]) -> io::Result<usize> {
        let mut packet = self
            .session
            .allocate_send_packet(buf.len().try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet is larger than u16::MAX",
                )
            })?)
            .map_err(|err| io::Error::new(io::ErrorKind::OutOfMemory, err))?;

        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);
        Ok(buf.len())
    }
}

impl Read for Queue {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_by_ref(buf)
    }
}

impl Write for Queue {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_by_ref(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Tun {
    queue: Queue,
    mtu: i32,
}

impl Tun {
    pub fn new(config: &Configuration) -> Result<Self> {
        if config.layer != Layer::L3 {
            return Err(Error::UnsupportedLayer);
        }

        let queue_number = config.queues.unwrap_or(1);
        if queue_number != 1 {
            return Err(Error::InvalidQueuesNumber);
        }

        let wintun = unsafe { load_from_path(&config.platform.wintun_file)? };
        let name = config.name.as_deref().unwrap_or("wintun");
        let adapter = match Adapter::open(&wintun, name) {
            // Wintun opens by name; device_guid only constrains newly-created adapters.
            Ok(adapter) => adapter,
            Err(_) => Adapter::create(&wintun, name, TUNNEL_TYPE, config.platform.device_guid)?,
        };

        let mut tun = Self {
            queue: Queue {
                session: Arc::new(adapter.start_session(config.platform.ring_capacity)?),
            },
            mtu: adapter
                .get_mtu()?
                .try_into()
                .map_err(|_| Error::InvalidConfig)?,
        };
        tun.configure(config)?;

        Ok(tun)
    }

    pub fn has_packet_information(&self) -> bool {
        self.queue.has_packet_information()
    }

    pub fn layer(&self) -> Layer {
        Layer::L3
    }

    pub fn set_nonblocking(&self) -> io::Result<()> {
        // Wintun exposes event-driven reads, but this blocking Read/Write API has no nonblocking mode.
        Ok(())
    }

    pub fn cancel_nonblocking(&self) -> io::Result<()> {
        self.queue
            .session
            .shutdown()
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(())
    }

    pub(crate) fn reader_queue(&self) -> Queue {
        self.queue.clone()
    }

    fn adapter(&self) -> Arc<Adapter> {
        self.queue.session.get_adapter()
    }

    fn first_ipv4(values: Vec<IpAddr>) -> Result<Ipv4Addr> {
        values
            .into_iter()
            // TODO: support an explicit selection policy if adapters commonly carry multiple IPv4 addresses.
            .find_map(|addr| match addr {
                IpAddr::V4(addr) => Some(addr),
                IpAddr::V6(_) => None,
            })
            .ok_or(Error::InvalidConfig)
    }
}

impl Interface for Tun {
    type Queue = Queue;

    fn name(&self) -> Result<String> {
        Ok(self.adapter().get_name()?)
    }

    fn set_name(&mut self, name: &str) -> Result<()> {
        Ok(self.adapter().set_name(name)?)
    }

    fn enable(&mut self, _value: bool) -> Result<()> {
        // Wintun adapter availability is bound to the session lifetime.
        Ok(())
    }

    fn flags(&self, _flags: Option<i16>) -> Result<i16> {
        Ok(0)
    }

    fn address(&self) -> Result<Ipv4Addr> {
        Self::first_ipv4(self.adapter().get_addresses()?)
    }

    fn set_address(&mut self, addr: Ipv4Addr) -> Result<()> {
        Ok(self.adapter().set_address(addr)?)
    }

    fn destination(&self) -> Result<Ipv4Addr> {
        Self::first_ipv4(self.adapter().get_gateways()?)
    }

    fn set_destination(&mut self, addr: Ipv4Addr) -> Result<()> {
        Ok(self.adapter().set_gateway(Some(addr))?)
    }

    fn broadcast(&self) -> Result<Ipv4Addr> {
        Err(Error::NotImplemented)
    }

    fn set_broadcast(&mut self, _addr: Ipv4Addr) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn netmask(&self) -> Result<Ipv4Addr> {
        match self
            .adapter()
            .get_netmask_of_address(&IpAddr::V4(self.address()?))?
        {
            IpAddr::V4(addr) => Ok(addr),
            IpAddr::V6(_) => Err(Error::InvalidConfig),
        }
    }

    fn set_netmask(&mut self, addr: Ipv4Addr) -> Result<()> {
        Ok(self.adapter().set_netmask(addr)?)
    }

    fn mtu(&self) -> Result<i32> {
        Ok(self.mtu)
    }

    fn set_mtu(&mut self, mtu: i32) -> Result<()> {
        sys::set_mtu(self.adapter().get_luid(), mtu)?;
        self.mtu = mtu;
        Ok(())
    }

    fn queue(&mut self) -> &mut Self::Queue {
        &mut self.queue
    }
}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.queue.read_by_ref(buf)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.queue.write_by_ref(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
