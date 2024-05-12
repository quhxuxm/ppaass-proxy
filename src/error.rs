use std::io::Error as StdIoError;
use std::net::AddrParseError;
use ppaass_codec::error::CodecError;
use ppaass_protocol::error::ProtocolError;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum ProxyServerError {
    #[error("Proxy server error happen because of io: {0:?}")]
    StdIo(#[from] StdIoError),
    #[error("Proxy server error happen when parse the addr: {0:?}")]
    AddrParse(#[from] AddrParseError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("Proxy server error happen because of reason: {0}")]
    Other(String),
}
