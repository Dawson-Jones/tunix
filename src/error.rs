use std::{ffi, io, num};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid configuration")]
    InvalidConfig,

    #[error("not implementated")]
    NotImplemented,

    #[error("device name too long")]
    NameTooLong,

    #[error("invalid device name")]
    InvalidName,

    #[error("invalid address")]
    InvalidAddress,

    #[error("unsuported network layer of operation")]
    UnsupportedLayer,

    #[error("invalid file descriptor")]
    InvalidDescriptor,

    #[error("invalid queues number")]
    InvalidQueuesNumber,

    #[cfg(unix)]
    #[error("{0}")]
    NixError(#[from] nix::Error),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Nul(#[from] ffi::NulError),

    #[error(transparent)]
    ParseNum(#[from] num::ParseIntError),

    #[cfg(target_os = "windows")]
    #[error(transparent)]
    WintunError(#[from] wintun::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
