use crate::{
    address::Ipv4AddrExt,
    configuration::{Configuration, Layer},
    error::{Error, Result},
    interface::Interface,
    platform::posix::{fd::Fd, name::write_if_name},
    syscall,
};
use libc::{c_int, c_short};
use std::{
    ffi::CStr,
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::fd::{AsRawFd, RawFd},
    sync::{Arc, Mutex},
};

use super::sys::*;

#[derive(Debug, Clone, Copy, Default)]
pub struct TunConf {
    pub(crate) packet_information: bool,
}

impl TunConf {
    pub fn packet_information(&mut self, value: bool) -> &mut Self {
        self.packet_information = value;
        self
    }
}

pub struct Queue {
    tun: Fd,
    pi_enabled: bool,
}

impl Queue {
    fn has_packet_information(&self) -> bool {
        self.pi_enabled
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        self.tun.set_nonblocking(true)
    }

    fn cancel_nonblocking(&self) -> io::Result<()> {
        self.tun.set_nonblocking(false)
    }
}

impl AsRawFd for Queue {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

pub struct Tun {
    name: Arc<Mutex<String>>,
    queue: Queue,
    ctl: Arc<Mutex<Fd>>,
}

impl Tun {
    pub fn new(config: &Configuration) -> Result<Self> {
        Tun::new_multi_queue(config)?
            .pop()
            .ok_or(Error::InvalidQueuesNumber)
    }

    pub fn new_multi_queue(config: &Configuration) -> Result<Vec<Self>> {
        let ctl_fd = syscall!(socket(libc::AF_INET, libc::SOCK_DGRAM, 0))?;
        let ctl = Fd::new(ctl_fd)?;
        let ctl = Arc::new(Mutex::new(ctl));
        let name = Arc::new(Mutex::new(String::new()));

        let mut tuns = Vec::new();
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

        if let Some(name) = config.name.as_ref() {
            write_if_name(name, &mut ifr.ifr_name)?;
        };

        let tun_type: c_short = config.layer.into();
        let queue_nums = config.queues.unwrap_or(1);
        if queue_nums < 1 {
            return Err(Error::InvalidQueuesNumber);
        }

        let pi = config.platform.packet_information;
        ifr.ifr_ifru.ifru_flags = tun_type
            | if pi { 0 } else { libc::IFF_NO_PI as c_short }
            | if queue_nums > 1 {
                libc::IFF_MULTI_QUEUE as c_short
            } else {
                0
            };

        for _ in 0..queue_nums {
            let tun_fd = syscall!(open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR))?;
            let tun_fd = Fd::new(tun_fd)?;

            unsafe {
                tunsetiff(
                    tun_fd.as_raw_fd(),
                    &mut ifr as *mut libc::ifreq as *mut c_int,
                )
            }?;

            let queue = Queue {
                tun: tun_fd,
                pi_enabled: pi,
            };
            let tun = Self {
                name: name.clone(),
                queue,
                ctl: ctl.clone(),
            };
            tuns.push(tun);
        }

        let name = unsafe {
            CStr::from_ptr(ifr.ifr_name.as_ptr())
                .to_string_lossy()
                .to_string()
        };
        *tuns[0].name.lock().unwrap() = name;

        tuns[0].configure(config)?;

        Ok(tuns)
    }

    fn ifreq(&self) -> libc::ifreq {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name = self.name.lock().unwrap();
        write_if_name(&name, &mut ifr.ifr_name).expect("stored interface name must be valid");

        ifr
    }

    pub fn set_nonblocking(&self) -> io::Result<()> {
        self.queue.set_nonblocking()
    }

    pub fn cancel_nonblocking(&self) -> io::Result<()> {
        self.queue.cancel_nonblocking()
    }

    pub fn has_packet_information(&self) -> bool {
        self.queue.has_packet_information()
    }
}

impl Interface for Tun {
    type Queue = Queue;

    fn name(&self) -> Result<String> {
        Ok(self.name.lock().unwrap().clone())
    }

    fn set_name(&mut self, new_name: &str) -> Result<()> {
        let mut ifr = self.ifreq();
        unsafe { write_if_name(new_name, &mut ifr.ifr_ifru.ifru_newname)? };

        unsafe { siocsifname(self.ctl.lock().unwrap().as_raw_fd(), &ifr) }?;

        *self.name.lock().unwrap() = new_name.into();

        Ok(())
    }

    fn enable(&mut self, value: bool) -> Result<()> {
        let mut flags = self.flags(None)?;

        if value {
            flags |= libc::IFF_UP as i16 | libc::IFF_RUNNING as i16;
        } else {
            flags &= !libc::IFF_UP as i16;
        }

        self.flags(Some(flags))?;

        Ok(())
    }

    fn flags(&self, flags: Option<i16>) -> Result<i16> {
        let mut ifr = self.ifreq();

        if let Some(flags) = flags {
            ifr.ifr_ifru.ifru_flags = flags;
            unsafe { siocsifflags(self.ctl.lock().unwrap().as_raw_fd(), &ifr) }?;
        } else {
            unsafe { siocgifflags(self.ctl.lock().unwrap().as_raw_fd(), &mut ifr) }?;
        }

        Ok(unsafe { ifr.ifr_ifru.ifru_flags })
    }

    fn address(&self) -> Result<Ipv4Addr> {
        let mut ifr = self.ifreq();

        unsafe { siocgifaddr(self.ctl.lock().unwrap().as_raw_fd(), &mut ifr) }?;

        Ok(Ipv4Addr::from_sockaddr(unsafe { ifr.ifr_ifru.ifru_addr }))
    }

    fn set_address(&mut self, addr: Ipv4Addr) -> Result<()> {
        let mut ifr = self.ifreq();
        ifr.ifr_ifru.ifru_addr = addr.to_sockaddr();

        unsafe { siocsifaddr(self.ctl.lock().unwrap().as_raw_fd(), &ifr) }?;

        Ok(())
    }

    fn destination(&self) -> Result<std::net::Ipv4Addr> {
        let mut ifr = self.ifreq();

        unsafe { siocgifdstaddr(self.ctl.lock().unwrap().as_raw_fd(), &mut ifr) }?;

        Ok(Ipv4Addr::from_sockaddr(unsafe { ifr.ifr_ifru.ifru_addr }))
    }

    fn set_destination(&mut self, addr: std::net::Ipv4Addr) -> Result<()> {
        let mut ifr = self.ifreq();
        ifr.ifr_ifru.ifru_addr = addr.to_sockaddr();

        unsafe { siocsifdstaddr(self.ctl.lock().unwrap().as_raw_fd(), &ifr) }?;

        Ok(())
    }

    fn broadcast(&self) -> Result<std::net::Ipv4Addr> {
        let mut ifr = self.ifreq();

        unsafe { siocgifbrdaddr(self.ctl.lock().unwrap().as_raw_fd(), &mut ifr) }?;

        Ok(Ipv4Addr::from_sockaddr(unsafe { ifr.ifr_ifru.ifru_addr }))
    }

    fn set_broadcast(&mut self, addr: std::net::Ipv4Addr) -> Result<()> {
        let mut ifr = self.ifreq();
        ifr.ifr_ifru.ifru_addr = addr.to_sockaddr();

        unsafe { siocsifbrdaddr(self.ctl.lock().unwrap().as_raw_fd(), &ifr) }?;

        Ok(())
    }

    fn netmask(&self) -> Result<std::net::Ipv4Addr> {
        let mut ifr = self.ifreq();

        unsafe { siocgifnetmask(self.ctl.lock().unwrap().as_raw_fd(), &mut ifr) }?;

        Ok(Ipv4Addr::from_sockaddr(unsafe { ifr.ifr_ifru.ifru_addr }))
    }

    fn set_netmask(&mut self, addr: std::net::Ipv4Addr) -> Result<()> {
        let mut ifr = self.ifreq();
        ifr.ifr_ifru.ifru_addr = addr.to_sockaddr();

        unsafe { siocsifnetmask(self.ctl.lock().unwrap().as_raw_fd(), &ifr) }?;

        Ok(())
    }

    fn mtu(&self) -> Result<i32> {
        let mut ifr = self.ifreq();

        unsafe { siocgifmtu(self.ctl.lock().unwrap().as_raw_fd(), &mut ifr) }?;

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu })
    }

    fn set_mtu(&mut self, mtu: i32) -> Result<()> {
        let mut ifr = self.ifreq();
        ifr.ifr_ifru.ifru_mtu = mtu;

        unsafe { siocsifmtu(self.ctl.lock().unwrap().as_raw_fd(), &ifr) }?;

        Ok(())
    }

    fn queue(&mut self) -> &mut Self::Queue {
        &mut self.queue
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.queue.as_raw_fd()
    }
}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.queue.tun.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.queue.tun.read_vectored(bufs)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.queue.tun.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.queue.tun.flush()
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.queue.tun.write_vectored(bufs)
    }
}

impl From<Layer> for c_short {
    fn from(value: Layer) -> Self {
        match value {
            Layer::L2 => libc::IFF_TAP as _,
            Layer::L3 => libc::IFF_TUN as _,
        }
    }
}
