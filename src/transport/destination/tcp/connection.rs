use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};

use futures_util::{
    stream::{SplitSink, SplitStream},
    Sink, Stream,
};

use pin_project::pin_project;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use tokio_util::codec::{BytesCodec, Framed};

use crate::error::ProxyError;

/// Define the simple alias for the write part
pub(crate) type DstConnectionWrite = SplitSink<DstTcpConnection<TcpStream>, Bytes>;

/// Define the simple alias for the read part
pub(crate) type DstConnectionRead = SplitStream<DstTcpConnection<TcpStream>>;

/// The destination connection framed with BytesCodec
#[pin_project]
pub(crate) struct DstTcpConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    /// The inner tcp framed that transfer data between proxy and destination
    #[pin]
    inner: Framed<T, BytesCodec>,
}

impl<T> DstTcpConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    /// Create a new destination connection
    /// * stream: The inner stream used to transfer data between proxy and destination
    /// * buffer_size: The data buffer size of the inner tcp stream
    pub fn new(stream: T, buffer_size: usize) -> Self {
        let inner = Framed::with_capacity(stream, BytesCodec::new(), buffer_size);
        Self { inner }
    }
}

/// Implemente the Sink trait for DstTcpConnection object
impl<T> Sink<Bytes> for DstTcpConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    type Error = ProxyError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        Sink::<Bytes>::poll_ready(this.inner, cx).map_err(ProxyError::Io)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.project();
        Sink::<Bytes>::start_send(this.inner, item).map_err(ProxyError::Io)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        Sink::<Bytes>::poll_flush(this.inner, cx).map_err(ProxyError::Io)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        Sink::<Bytes>::poll_close(this.inner, cx).map_err(ProxyError::Io)
    }
}

/// Implemente the Stream trait for DstTcpConnection object
impl<T> Stream for DstTcpConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    type Item = Result<BytesMut, ProxyError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx).map_err(ProxyError::Io)
    }
}
