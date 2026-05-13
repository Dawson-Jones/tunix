use std::io;

use windows::Win32::{
    NetworkManagement::{
        IpHelper::{
            GetIpInterfaceEntry, InitializeIpInterfaceEntry, SetIpInterfaceEntry,
            MIB_IPINTERFACE_ROW,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::AF_INET,
};

pub fn set_mtu(luid: NET_LUID_LH, mtu: i32) -> io::Result<()> {
    let mtu = mtu
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "MTU must be non-negative"))?;

    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe {
        InitializeIpInterfaceEntry(&mut row);
    }
    row.Family = AF_INET;
    row.InterfaceLuid = luid;

    unsafe {
        GetIpInterfaceEntry(&mut row).map_err(io::Error::other)?;
    }
    row.NlMtu = mtu;
    unsafe {
        SetIpInterfaceEntry(&mut row).map_err(io::Error::other)?;
    }

    Ok(())
}
