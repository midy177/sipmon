use thiserror::Error;

/// Error taxonomy (kept for library-style consumers of the modules).
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pcap: {0}")]
    Pcap(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("evlog: {0}")]
    Evlog(String),
    #[error("{0}")]
    Other(String),
}

#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, Error>;
