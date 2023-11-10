use std::io::Error as StdIoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum ProxyError {
    #[error("I/O error happen: {0:?}")]
    Io(#[from] StdIoError),
    #[error("Other error happen: {0}")]
    Other(String),
}
