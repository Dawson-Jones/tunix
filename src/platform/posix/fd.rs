use crate::platform::posix::sys::{cvt, cvt_ssize};
#[cfg(target_os = "linux")]
use std::ffi::CStr;
use std::{
    io::{self, Read, Write},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};

pub(crate) struct Fd(OwnedFd);

impl Fd {
    fn from_syscall(fd: RawFd) -> io::Result<Self> {
        let fd = cvt(fd)?;
        // SAFETY: fd was just returned by an fd-creating system call and ownership
        // is transferred exactly once into this function.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let flags = cvt(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) })?;
        cvt(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) })?;

        Ok(Self(fd))
    }

    pub fn socket(domain: libc::c_int, ty: libc::c_int, protocol: libc::c_int) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        let ty = ty | libc::SOCK_CLOEXEC;
        // SAFETY: socket has no pointer arguments and the returned descriptor is
        // immediately transferred to OwnedFd.
        Self::from_syscall(unsafe { libc::socket(domain, ty, protocol) })
    }

    #[cfg(target_os = "linux")]
    pub fn open(path: &CStr, flags: libc::c_int) -> io::Result<Self> {
        // SAFETY: path is NUL-terminated and remains alive for the duration of the call.
        Self::from_syscall(unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) })
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut now = cvt(unsafe { libc::fcntl(self.as_raw_fd(), libc::F_GETFL) })?;

        if nonblocking {
            now |= libc::O_NONBLOCK;
        } else {
            now &= !libc::O_NONBLOCK;
        }

        cvt(unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, now) }).map(|_| ())
    }
}

impl AsFd for Fd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl Read for Fd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: buf is writable for buf.len() bytes and the fd remains valid.
        let n = cvt_ssize(unsafe {
            libc::read(
                self.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        })?;

        Ok(n as _)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        let iov = bufs.as_ptr().cast();
        let iovcnt = bufs.len().min(libc::c_int::MAX as usize) as _;

        // SAFETY: IoSliceMut is ABI-compatible with iovec and each slice is writable.
        let n = cvt_ssize(unsafe { libc::readv(self.as_raw_fd(), iov, iovcnt) })?;

        Ok(n as _)
    }
}

impl Write for Fd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: buf is readable for buf.len() bytes and the fd remains valid.
        let n = cvt_ssize(unsafe {
            libc::write(
                self.as_raw_fd(),
                buf.as_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        })?;

        Ok(n as _)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let iov = bufs.as_ptr().cast();
        let iovcnt = bufs.len().min(libc::c_int::MAX as usize) as _;

        // SAFETY: IoSlice is ABI-compatible with iovec and each slice is readable.
        let n = cvt_ssize(unsafe { libc::writev(self.as_raw_fd(), iov, iovcnt) })?;

        Ok(n as _)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Fd;
    use crate::platform::posix::sys::cvt;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;

    #[test]
    fn owns_cloexec_descriptor_and_reads_into_mutable_buffer() {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors has space for the two fds written by pipe.
        cvt(unsafe { libc::pipe(descriptors.as_mut_ptr()) }).unwrap();
        let mut reader = Fd::from_syscall(descriptors[0]).unwrap();
        let mut writer = Fd::from_syscall(descriptors[1]).unwrap();

        let flags = cvt(unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFD) }).unwrap();
        assert_ne!(flags & libc::FD_CLOEXEC, 0);

        writer.write_all(b"tunix").unwrap();
        let mut received = [0; 5];
        reader.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"tunix");
    }
}
