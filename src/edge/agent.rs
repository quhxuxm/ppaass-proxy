use std::{
    fmt::{Debug, Formatter},
    pin::Pin,
    task::{Context, Poll},
};

use crate::crypto::ProxyRsaCryptoFetcher;
use crate::error::ProxyError;
use bytes::BytesMut;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, Stream};
use pin_project::pin_project;
use ppaass_codec::codec::agent::decoder::AgentMessageDecoder;
use ppaass_codec::codec::proxy::encoder::ProxyMessageEncoder;
use ppaass_crypto::RsaCryptoFetcher;
use ppaass_protocol::message::agent::AgentMessage;
use ppaass_protocol::message::proxy::ProxyMessage;
use std::fmt::Result as FmtResult;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Encoder, Framed};
use uuid::Uuid;

pub(crate) type AgentEdgeWrite =
    SplitSink<AgentEdge<TcpStream, Arc<ProxyRsaCryptoFetcher>>, ProxyMessage>;

pub(crate) type AgentEdgeRead = SplitStream<AgentEdge<TcpStream, Arc<ProxyRsaCryptoFetcher>>>;

struct AgentEdgeCodec<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    decoder: AgentMessageDecoder<F>,
    encoder: ProxyMessageEncoder<F>,
}

impl<F> AgentEdgeCodec<F>
where
    F: RsaCryptoFetcher + Send + Sync + Clone + 'static,
{
    fn new(compress: bool, rsa_crypto_fetcher: F) -> Self {
        Self {
            decoder: AgentMessageDecoder::new(rsa_crypto_fetcher.clone()),
            encoder: ProxyMessageEncoder::new(compress, rsa_crypto_fetcher),
        }
    }
}

impl<F> Decoder for AgentEdgeCodec<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    type Item = AgentMessage;
    type Error = ProxyError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decoder.decode(src).map_err(ProxyError::Decoder)
    }
}

impl<F> Encoder<ProxyMessage> for AgentEdgeCodec<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    type Error = ProxyError;

    fn encode(&mut self, item: ProxyMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encoder.encode(item, dst).map_err(ProxyError::Encoder)
    }
}

#[pin_project]
pub(crate) struct AgentEdge<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    #[pin]
    inner: Framed<T, AgentEdgeCodec<F>>,
    connection_id: String,
    _marker: PhantomData<F>,
}

impl<T, F> AgentEdge<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    F: RsaCryptoFetcher + Send + Sync + Clone + 'static,
{
    pub fn new(
        stream: T,
        rsa_crypto_fetcher: F,
        compress: bool,
        buffer_size: usize,
    ) -> AgentEdge<T, F> {
        let connection_codec = AgentEdgeCodec::new(compress, rsa_crypto_fetcher);
        let inner = Framed::with_capacity(stream, connection_codec, buffer_size);
        Self {
            inner,
            connection_id: Uuid::new_v4().to_string(),
            _marker: PhantomData,
        }
    }
}

impl<T, F> Debug for AgentEdge<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("AgentConnection")
            .field("connection_id", &self.connection_id)
            .field("inner", &"<OBJ>")
            .finish()
    }
}

impl<T, F> Sink<ProxyMessage> for AgentEdge<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    type Error = ProxyError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: ProxyMessage) -> Result<(), Self::Error> {
        let this = self.project();
        this.inner.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_close(cx)
    }
}

impl<T, F> Stream for AgentEdge<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    type Item = Result<AgentMessage, ProxyError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx)
    }
}
