use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::error::{Error, Result};

pub trait IntoIpv4Addr {
    fn into_ipv4(&self) -> Result<Ipv4Addr>;
}

impl IntoIpv4Addr for u32 {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        Ok(Ipv4Addr::from(*self))
    }
}

impl IntoIpv4Addr for i32 {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        Ok(Ipv4Addr::from(*self as u32))
    }
}

impl IntoIpv4Addr for (u8, u8, u8, u8) {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        Ok(Ipv4Addr::new(self.0, self.1, self.2, self.3))
    }
}

impl IntoIpv4Addr for str {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        self.parse().map_err(|_| Error::InvalidAddress)
    }
}

impl IntoIpv4Addr for &str {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        (*self).into_ipv4()
    }
}

impl IntoIpv4Addr for String {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        self.as_str().into_ipv4()
    }
}

impl IntoIpv4Addr for &String {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        (**self).into_ipv4()
    }
}

impl IntoIpv4Addr for Ipv4Addr {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        Ok(*self)
    }
}

impl IntoIpv4Addr for &Ipv4Addr {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        Ok(**self)
    }
}

impl IntoIpv4Addr for IpAddr {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        match self {
            IpAddr::V4(addr) => Ok(*addr),
            _ => Err(Error::InvalidAddress),
        }
    }
}

impl IntoIpv4Addr for &IpAddr {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        (*self).into_ipv4()
    }
}

impl IntoIpv4Addr for SocketAddrV4 {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        self.ip().into_ipv4()
    }
}

impl IntoIpv4Addr for &SocketAddrV4 {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        (*self).into_ipv4()
    }
}

impl IntoIpv4Addr for SocketAddr {
    fn into_ipv4(&self) -> Result<Ipv4Addr> {
        match self {
            SocketAddr::V4(addr) => addr.into_ipv4(),
            _ => Err(Error::InvalidAddress),
        }
    }
}

#[cfg(unix)]
pub trait Ipv4AddrExt {
    fn to_sockaddr(&self) -> libc::sockaddr;
    fn from_sockaddr(sock: libc::sockaddr) -> Self;
}

#[cfg(unix)]
impl Ipv4AddrExt for Ipv4Addr {
    fn to_sockaddr(&self) -> libc::sockaddr {
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as _;
        // addr.sin_port = 0;
        addr.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(self.octets()),
        };
        unsafe { std::mem::transmute(addr) }
    }

    fn from_sockaddr(addr: libc::sockaddr) -> Self {
        let addr: libc::sockaddr_in = unsafe { std::mem::transmute(addr) };
        // network byte order to host byte order
        addr.sin_addr.s_addr.to_ne_bytes().into()
    }
}
