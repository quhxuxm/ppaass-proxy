use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures_util::{Sink, SinkExt, Stream, StreamExt, TryFutureExt};
use log::error;
use pin_project::pin_project;
use ppaass_crypto::random_16_bytes;
use ppaass_protocol::message::{
    AgentTcpPayload, Encryption, NetAddress, PayloadType, ProxyTcpPayload, WrapperMessage,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{mpsc::channel, Mutex},
};

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
    transport_id: String,
    agent_recv_buf: Arc<Mutex<VecDeque<u8>>>,
}

impl<T> DestTcpHandler<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub fn new(
        transport_id: String,
        agent_connection_read: AgentConnectionRead<T>,
        agent_connection_write: AgentConnectionWrite<T>,
    ) -> Self {
        Self {
            transport_id,
            agent_connection_read,
            agent_connection_write,
            agent_recv_buf: Arc::new(Mutex::new(VecDeque::with_capacity(65536))),
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
                return Err(ProxyError::Other(format!("The first agent message should be init request but not the data, transport: {}, agent connection: {connection_id}", self.transport_id)));
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
                    connection_id: self.transport_id.clone(),
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

        self.start_receive_agent_message();

        todo!()
    }

    fn start_receive_agent_message(mut self) {
        let agent_recv_buf = self.agent_recv_buf.clone();
        tokio::spawn(async move {
            loop {
                let agent_wrapped_message = match tokio::time::timeout(
                    Duration::from_secs(30),
                    self.agent_connection_read.next(),
                )
                .await
                {
                    Ok(Some(Ok(agent_wrapper_message))) => agent_wrapper_message,
                    Ok(Some(Err(e))) => {
                        error!(
                            "Fail to read agent connection because of timeout, transport: {}",
                            self.transport_id
                        );
                        return;
                    }
                    Ok(None) => {
                        return;
                    }
                    Err(_) => {
                        error!(
                            "Fail to read agent connection because of timeout, transport: {}",
                            self.transport_id
                        );
                        return;
                    }
                };
                if agent_wrapped_message.payload_type != PayloadType::Tcp {
                    error!(
                "Incoming message is not a Tcp message, the transport [{}] in invalid status.",
                self.transport_id);
                    return;
                }
                let agent_tcp_payload: AgentTcpPayload = match agent_wrapped_message
                    .payload
                    .try_into()
                {
                    Ok(agent_tcp_payload) => agent_tcp_payload,
                    Err(e) => {
                        error!("Fail to parse agent tcp payload because of error on transport [{}]: {e:?}.", self.transport_id);
                        return;
                    }
                };
                let AgentTcpPayload::Data {
                    connection_id,
                    data,
                } = agent_tcp_payload
                else {
                    error!("Incoming message is not a Data message, the transport [{}] in invalid status.",self.transport_id);
                    return;
                };
                let mut agent_recv_buf = agent_recv_buf.lock().await;
                agent_recv_buf.extend(data);
            }
        });
    }
}
