use libc::{c_int, ifreq};

nix::ioctl_read_bad!(siocgifflags, 0x8913, ifreq); // get flags
nix::ioctl_write_ptr_bad!(siocsifflags, 0x8914, ifreq); // set flags

nix::ioctl_read_bad!(siocgifaddr, 0x8915, ifreq); // get PA address
nix::ioctl_write_ptr_bad!(siocsifaddr, 0x8916, ifreq); // set PA address

nix::ioctl_read_bad!(siocgifdstaddr, 0x8917, ifreq); // get remote PA address
nix::ioctl_write_ptr_bad!(siocsifdstaddr, 0x8918, ifreq); // set remote PA address

nix::ioctl_read_bad!(siocgifbrdaddr, 0x8919, ifreq); // get broadcast PA address
nix::ioctl_write_ptr_bad!(siocsifbrdaddr, 0x891a, ifreq); // set broadcast PA address

nix::ioctl_read_bad!(siocgifnetmask, 0x891b, ifreq); // get network PA mask
nix::ioctl_write_ptr_bad!(siocsifnetmask, 0x891c, ifreq); // set network PA mask

nix::ioctl_read_bad!(siocgifmtu, 0x8921, ifreq); // get MTU size
nix::ioctl_write_ptr_bad!(siocsifmtu, 0x8922, ifreq); // set MTU size

nix::ioctl_read_bad!(siocgifname, 0x8910, ifreq); // get iface name
nix::ioctl_write_ptr_bad!(siocsifname, 0x8923, ifreq); // set interface name

nix::ioctl_write_ptr!(tunsetiff, b'T', 202, c_int);
nix::ioctl_write_ptr!(tunsetpersist, b'T', 203, c_int);
nix::ioctl_write_ptr!(tunsetowner, b'T', 204, c_int);
nix::ioctl_write_ptr!(tunsetgroup, b'T', 205, c_int);
