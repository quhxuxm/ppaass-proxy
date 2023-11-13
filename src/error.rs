use ppaass_io::{DecoderError, EncoderError};
use ppaass_protocol::error::ProtocolError;
use std::io::Error as StdIoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum ProxyError {
    #[error("Timeout error happen: {0}")]
    Timeout(u64),
    #[error("I/O error happen: {0:?}")]
    Io(#[from] StdIoError),
    #[error("Decoder error happen: {0:?}")]
    Decoder(#[from] DecoderError),
    #[error("Encoder error happen: {0:?}")]
    Encoder(#[from] EncoderError),
    #[error("Protocol error happen: {0:?}")]
    Protocol(#[from] ProtocolError),
    #[error("Other error happen: {0}")]
    Other(String),
}
