use ppaass_codec::error::CodecError;
use ppaass_protocol::error::ProtocolError;
use std::io::Error as StdIoError;
use thiserror::Error;
#[derive(Debug, Error)]
pub(crate) enum ProxyServerError {
    #[error("Proxy server error happen because of io: {0:?}")]
    StdIo(#[from] StdIoError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("Proxy server error happen because of reason: {0}")]
    Other(String),
}
