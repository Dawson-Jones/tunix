use std::io::{self, Read, Write};
use std::task::{Poll, ready};

use crate::interface::Interface;
use crate::{error::Result, tun::Tun};
#[cfg(target_os = "windows")]
use bytes::Bytes;
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(target_os = "windows")]
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

use super::codec::TunPacketCodec;

const DEFAULT_MTU: usize = 1500;

#[cfg(unix)]
pub struct AsyncTun {
    inner: AsyncFd<Tun>,
}

#[cfg(target_os = "windows")]
pub struct AsyncTun {
    inner: Tun,
    read_rx: mpsc::Receiver<io::Result<Bytes>>,
    pending_read: Bytes,
}

#[cfg(target_os = "windows")]
const READ_QUEUE_CAPACITY: usize = 64;

impl AsyncTun {
    pub fn new(tun: Tun) -> Result<AsyncTun> {
        Self::new_inner(tun)
    }

    pub fn new_multi_queue(tuns: Vec<Tun>) -> Result<Vec<AsyncTun>> {
        tuns.into_iter().map(AsyncTun::new).collect()
    }

    pub fn into_framed(self) -> Framed<Self, TunPacketCodec> {
        let pi = self.get_ref().has_packet_information();
        let layer = self.get_ref().layer();
        let mtu = self
            .get_ref()
            .mtu()
            .ok()
            .and_then(|mtu| usize::try_from(mtu).ok())
            .filter(|mtu| *mtu > 0)
            .unwrap_or(DEFAULT_MTU);
        let codec = TunPacketCodec::new(pi, layer, mtu);
        let capacity = codec.frame_capacity();

        Framed::with_capacity(self, codec, capacity)
    }
}

#[cfg(unix)]
impl AsyncTun {
    fn new_inner(tun: Tun) -> Result<AsyncTun> {
        tun.set_nonblocking()?;

        Ok(AsyncTun {
            inner: AsyncFd::new(tun)?,
        })
    }

    pub fn get_ref(&self) -> &Tun {
        self.inner.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut Tun {
        self.inner.get_mut()
    }
}

#[cfg(target_os = "windows")]
impl AsyncTun {
    fn new_inner(tun: Tun) -> Result<AsyncTun> {
        let mut reader = tun.reader_queue();
        let (read_tx, read_rx) = mpsc::channel(READ_QUEUE_CAPACITY);
        let mtu = tun
            .mtu()
            .ok()
            .and_then(|mtu| usize::try_from(mtu).ok())
            .filter(|mtu| *mtu > 0)
            .unwrap_or(DEFAULT_MTU);
        std::thread::Builder::new()
            .name("tunix-wintun-reader".into())
            .spawn(move || {
                let mut buf = vec![0u8; mtu];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => {
                            if read_tx
                                .blocking_send(Ok(Bytes::copy_from_slice(&buf[..n])))
                                .is_err()
                            {
                                return;
                            }
                        }
                        Err(error) => {
                            let _ = read_tx.blocking_send(Err(error));
                            return;
                        }
                    }
                }
            })?;

        Ok(AsyncTun {
            inner: tun,
            read_rx,
            pending_read: Bytes::new(),
        })
    }

    pub fn get_ref(&self) -> &Tun {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut Tun {
        &mut self.inner
    }
}

#[cfg(unix)]
impl AsyncRead for AsyncTun {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let self_mut = self.get_mut();
        loop {
            let mut guard = ready!(self_mut.inner.poll_read_ready_mut(cx))?;
            let rbuf = buf.initialize_unfilled();
            match guard.try_io(|inner| inner.get_mut().read(rbuf)) {
                Ok(res) => return Poll::Ready(res.map(|n| buf.advance(n))),
                Err(_wb) => continue,
            }
        }
    }
}

#[cfg(unix)]
impl AsyncWrite for AsyncTun {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let self_mut = self.get_mut();
        loop {
            let mut guard = ready!(self_mut.inner.poll_write_ready_mut(cx))?;

            match guard.try_io(|inner| inner.get_mut().write(buf)) {
                Ok(res) => return Poll::Ready(res),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let self_mut = self.get_mut();
        loop {
            let mut guard = ready!(self_mut.inner.poll_write_ready_mut(cx))?;

            match guard.try_io(|inner| inner.get_mut().flush()) {
                Ok(res) => return Poll::Ready(res),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(target_os = "windows")]
impl AsyncRead for AsyncTun {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let self_mut = self.get_mut();
        loop {
            if !self_mut.pending_read.is_empty() {
                let n = self_mut.pending_read.len().min(buf.remaining());
                buf.put_slice(&self_mut.pending_read.split_to(n));
                return Poll::Ready(Ok(()));
            }

            match ready!(self_mut.read_rx.poll_recv(cx)) {
                Some(Ok(packet)) => self_mut.pending_read = packet,
                Some(Err(error)) => return Poll::Ready(Err(error)),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl AsyncWrite for AsyncTun {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(self.get_mut().inner.write(buf))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.get_mut().inner.flush())
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let _ = self.get_mut().inner.cancel_nonblocking();
        Poll::Ready(Ok(()))
    }
}

#[cfg(target_os = "windows")]
impl Drop for AsyncTun {
    fn drop(&mut self) {
        // Closing the bounded channel releases a reader blocked by backpressure;
        // shutting down the session releases one blocked in receive_blocking.
        // The worker owns only an Arc-backed queue, so it can finish independently
        // without making Drop wait on an unbounded thread join.
        self.read_rx.close();
        let _ = self.inner.cancel_nonblocking();
    }
}
