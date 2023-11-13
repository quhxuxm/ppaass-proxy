use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures_util::{Sink, SinkExt, Stream, StreamExt, TryFutureExt};
use pin_project::pin_project;
use ppaass_crypto::random_16_bytes;
use ppaass_protocol::message::{
    AgentTcpPayload, Encryption, NetAddress, PayloadType, ProxyTcpPayload, WrapperMessage,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::mpsc::channel,
};
use tokio_stream::StreamExt as TokioStreamExt;
use tokio_util::codec::{BytesCodec, Framed};

use crate::{
    error::ProxyError,
    types::{AgentConnectionRead, AgentConnectionWrite},
};

use super::HandlerInput;

/// The destination connection framed with BytesCodec
#[pin_project]
pub(crate) struct DestTcpConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    #[pin]
    inner: Framed<T, BytesCodec>,
}

impl<T> DestTcpConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub fn new(stream: T, buffer_size: usize) -> Self {
        let inner = Framed::with_capacity(stream, BytesCodec::new(), buffer_size);
        Self { inner }
    }
}

impl<T> Sink<Bytes> for DestTcpConnection<T>
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

impl<T> Stream for DestTcpConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    type Item = Result<BytesMut, ProxyError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx).map_err(ProxyError::Io)
    }
}

pub(crate) struct DestTcpHandler<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    agent_connection_read: AgentConnectionRead<T>,
    agent_connection_write: AgentConnectionWrite<T>,
}

impl<T> DestTcpHandler<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub fn new(
        agent_connection_read: AgentConnectionRead<T>,
        agent_connection_write: AgentConnectionWrite<T>,
    ) -> Self {
        Self {
            agent_connection_read,
            agent_connection_write,
        }
    }

    pub async fn handle(mut self, input: HandlerInput) -> Result<(), ProxyError> {
        let HandlerInput {
            unique_id,
            user_token,
            payload,
        } = input;
        let agent_tcp_payload: AgentTcpPayload = payload.try_into()?;
        let dest_tcp_connection = match agent_tcp_payload {
            AgentTcpPayload::Data { connection_id, .. } => {
                // The first agent message should be init request but not the data.
                return Err(ProxyError::Other(format!("The first agent message should be init request but not the data, agent connection: {connection_id}")));
            }
            AgentTcpPayload::InitRequest {
                src_address,
                dst_address,
            } => {
                // The first agent agenmt message is init request
                // which is used for initialize destination tcp connection
                let dest_tcp_stream = match &dst_address {
                    NetAddress::Ip(ip_addr) => TcpStream::connect(ip_addr).await?,
                    NetAddress::Domain { host, port } => {
                        TcpStream::connect((host.as_ref(), *port)).await?
                    }
                };
                // Generate proxy init response message
                let proxy_init_response = ProxyTcpPayload::InitResponse {
                    connection_id: String::from_utf8_lossy(random_16_bytes().as_ref()).to_string(),
                    src_address,
                    dst_address,
                };
                let encryption = Encryption::Aes(random_16_bytes());
                let wrapped_message = WrapperMessage::new(
                    unique_id,
                    user_token,
                    encryption,
                    PayloadType::Tcp,
                    proxy_init_response.try_into()?,
                );
                self.agent_connection_write.send(wrapped_message).await?;

                DestTcpConnection::new(dest_tcp_stream, 65536)
            }
        };
        let (dest_tcp_write, dest_tcp_read) = dest_tcp_connection.split();

        let (dest_relay_tx, dest_relay_rx) = channel(1024);

        TokioStreamExt::map_while(
            self.agent_connection_read.timeout(Duration::from_secs(20)),
            |item| {
                let agent_wrapped_message = item.ok()?.ok()?;
                if agent_wrapped_message.payload_type != PayloadType::Tcp {
                    return None;
                }
                let agent_tcp_payload: AgentTcpPayload =
                    agent_wrapped_message.payload.try_into().ok()?;
                let AgentTcpPayload::Data {
                    connection_id,
                    data,
                } = agent_tcp_payload
                else {
                    return None;
                };
                Some(Ok(data))
            },
        )
        .forward(dest_relay_tx);

        todo!()
    }
}
