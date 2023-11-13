use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures_util::{
    stream::{SplitSink, SplitStream},
    Sink, SinkExt, Stream, StreamExt,
};
use log::error;
use pin_project::pin_project;
use ppaass_crypto::random_16_bytes;
use ppaass_protocol::message::{
    AgentTcpPayload, Encryption, NetAddress, PayloadType, ProxyTcpPayload, WrapperMessage,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::mpsc::{channel, Receiver, Sender},
};

use tokio_util::codec::{BytesCodec, Framed};

use crate::{
    error::ProxyError,
    types::{AgentConnectionRead, AgentConnectionWrite},
};

use super::HandlerInput;

type DestConnectionWrite = SplitSink<DestTcpConnection<TcpStream>, Bytes>;

type DestConnectionRead = SplitStream<DestTcpConnection<TcpStream>>;

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
    agent_recv_buf_tx: Sender<Bytes>,
    agent_recv_buf_rx: Receiver<Bytes>,
    dest_recv_buf_tx: Sender<Bytes>,
    dest_recv_buf_rx: Receiver<Bytes>,
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
        let (agent_recv_buf_tx, agent_recv_buf_rx) = channel(1024);
        let (dest_recv_buf_tx, dest_recv_buf_rx) = channel(1024);
        Self {
            transport_id,
            agent_connection_read,
            agent_connection_write,
            agent_recv_buf_tx,
            agent_recv_buf_rx,
            dest_recv_buf_tx,
            dest_recv_buf_rx,
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
                    user_token.clone(),
                    encryption,
                    PayloadType::Tcp,
                    proxy_init_response.try_into()?,
                );
                self.agent_connection_write.send(wrapped_message).await?;
                DestTcpConnection::new(dest_tcp_stream, 65536)
            }
        };
        let (dest_connection_write, dest_connection_read) = dest_tcp_connection.split();

        Self::start_receive_agent_message(
            self.transport_id.clone(),
            self.agent_recv_buf_tx,
            self.agent_connection_read,
        );

        Self::start_relay_agent_to_dest(
            self.transport_id.clone(),
            self.agent_recv_buf_rx,
            dest_connection_write,
        );

        Self::start_relay_dest_to_agent(
            self.transport_id.clone(),
            user_token,
            self.dest_recv_buf_rx,
            self.agent_connection_write,
        );

        Self::start_receive_dest_message(
            self.transport_id,
            self.dest_recv_buf_tx,
            dest_connection_read,
        );
        Ok(())
    }

    /// Read the dest receive buffer to agent
    fn start_relay_dest_to_agent(
        transport_id: String,
        user_token: String,
        mut dest_recv_buf_rx: Receiver<Bytes>,
        mut agent_connection_write: AgentConnectionWrite<T>,
    ) {
        tokio::spawn(async move {
            while let Some(dest_data_to_send) = dest_recv_buf_rx.recv().await {
                let payload = AgentTcpPayload::Data {
                    connection_id: transport_id.clone(),
                    data: dest_data_to_send,
                }
                .try_into();
                let payload: Bytes = match payload {
                    Ok(payload) => payload,
                    Err(e) => {
                        error!("Transport [{transport_id}] fail to serialize agent tcp payload because of error: {e:?}");
                        return;
                    }
                };
                let dest_data_to_agent_message = WrapperMessage::new(
                    String::from_utf8_lossy(random_16_bytes().as_ref()).to_string(),
                    user_token.clone(),
                    Encryption::Aes(random_16_bytes()),
                    PayloadType::Tcp,
                    payload,
                );
                if let Err(e) = agent_connection_write
                    .send(dest_data_to_agent_message)
                    .await
                {
                    error!("Transport [{transport_id}] fail to send agent recv buffer data to destination because of error: {e:?}");
                    continue;
                };
            }
        });
    }

    /// Read the agent data to receive buffer
    fn start_receive_dest_message(
        transport_id: String,
        dest_recv_buf_tx: Sender<Bytes>,
        mut dest_connection_read: DestConnectionRead,
    ) {
        tokio::spawn(async move {
            loop {
                let dest_message = match tokio::time::timeout(
                    Duration::from_secs(20),
                    dest_connection_read.next(),
                )
                .await
                {
                    Ok(Some(Ok(dest_message))) => dest_message,
                    Ok(Some(Err(e))) => {
                        error!(
                            "Transport [{transport_id}] fail to read dest connection because of error: {e:?}"
                        );
                        return;
                    }
                    Ok(None) => {
                        return;
                    }
                    Err(_) => {
                        error!(
                            "Fail to read dest connection because of timeout, transport: {transport_id}"
                        );
                        return;
                    }
                };
                if let Err(e) = dest_recv_buf_tx.send(dest_message.freeze()).await {
                    error!("Transport [{transport_id}] fail to send dest data to relay because of error: {e:?}");
                };
            }
        });
    }

    /// Read the agent receive buffer to destiation
    fn start_relay_agent_to_dest(
        transport_id: String,
        mut agent_recv_buf_rx: Receiver<Bytes>,
        mut dest_connection_write: DestConnectionWrite,
    ) {
        tokio::spawn(async move {
            while let Some(agent_data_to_send) = agent_recv_buf_rx.recv().await {
                if let Err(e) = dest_connection_write.send(agent_data_to_send).await {
                    error!("Transport [{transport_id}] fail to send agent recv buffer data to destination because of error: {e:?}");
                    continue;
                };
            }
        });
    }

    /// Read the agent data to receive buffer
    fn start_receive_agent_message(
        transport_id: String,
        agent_recv_buf_tx: Sender<Bytes>,
        mut agent_connection_read: AgentConnectionRead<T>,
    ) {
        tokio::spawn(async move {
            loop {
                let agent_wrapped_message = match tokio::time::timeout(
                    Duration::from_secs(30),
                    agent_connection_read.next(),
                )
                .await
                {
                    Ok(Some(Ok(agent_wrapper_message))) => agent_wrapper_message,
                    Ok(Some(Err(e))) => {
                        error!(
                            "Transport [{transport_id}] fail to read agent connection because of error: {e:?}"
                        );
                        return;
                    }
                    Ok(None) => {
                        return;
                    }
                    Err(_) => {
                        error!(
                            "Fail to read agent connection because of timeout, transport: {transport_id}"
                        );
                        return;
                    }
                };
                if agent_wrapped_message.payload_type != PayloadType::Tcp {
                    error!("Incoming message is not a Tcp message, the transport [{transport_id}] in invalid status.");
                    return;
                }
                let agent_tcp_payload: AgentTcpPayload = match agent_wrapped_message
                    .payload
                    .try_into()
                {
                    Ok(agent_tcp_payload) => agent_tcp_payload,
                    Err(e) => {
                        error!("Fail to parse agent tcp payload because of error on transport [{transport_id}]: {e:?}.");
                        return;
                    }
                };

                let AgentTcpPayload::Data { data, .. } = agent_tcp_payload else {
                    error!("Incoming message is not a Data message, the transport [{transport_id}] in invalid status.");
                    return;
                };
                if let Err(e) = agent_recv_buf_tx.send(data).await {
                    error!("Transport [{transport_id}] fail to send agent data to relay because of error: {e:?}");
                };
            }
        });
    }
}
