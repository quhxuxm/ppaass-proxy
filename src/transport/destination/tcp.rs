use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures_channel::mpsc::{channel, Receiver, Sender};
use futures_util::{
    stream::{SplitSink, SplitStream},
    Sink, SinkExt, Stream, StreamExt,
};
use log::{debug, error};
use pin_project::pin_project;

use ppaass_protocol::message::{
    AgentTcpPayload, NetAddress, UnwrappedAgentTcpPayload, WrapperMessage,
};
use ppaass_protocol::unwrap_agent_tcp_payload;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use tokio_util::codec::{BytesCodec, Framed};

use crate::{
    error::ProxyError,
    types::{AgentConnectionRead, AgentConnectionWrite},
};

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

    pub async fn handle(mut self, input: WrapperMessage) -> Result<(), ProxyError> {
        let UnwrappedAgentTcpPayload {
            user_token,
            payload,
            ..
        } = unwrap_agent_tcp_payload(input)?;
        let dest_tcp_connection = match payload {
            AgentTcpPayload::Data { connection_id, .. } => {
                // The first agent message should be init request but not the data.
                return Err(ProxyError::Other(format!("The first agent message should be init request but not the data, transport: {}, agent connection: {connection_id}", self.transport_id)));
            }
            AgentTcpPayload::InitRequest {
                src_address,
                dst_address,
            } => {
                // The first agent agent message is init request
                // which is used for initialize destination tcp connection
                debug!("Going to connect destination: {dst_address:?}");
                let dest_tcp_stream = match &dst_address {
                    NetAddress::Ip(ip_addr) => TcpStream::connect(ip_addr).await?,
                    NetAddress::Domain { host, port } => {
                        TcpStream::connect((host.as_ref(), *port)).await?
                    }
                };

                debug!("Success connect to destination: {dst_address:?}");

                // Generate success proxy init response message
                let tcp_init_success_response =
                    ppaass_protocol::new_proxy_tcp_init_success_response(
                        self.transport_id.clone(),
                        user_token.clone(),
                        src_address,
                        dst_address,
                    )?;
                self.agent_connection_write
                    .send(tcp_init_success_response)
                    .await?;
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
            while let Some(dest_data) = dest_recv_buf_rx.next().await {
                let proxy_data_message = match ppaass_protocol::new_proxy_tcp_data(
                    user_token.clone(),
                    transport_id.clone(),
                    dest_data,
                ) {
                    Ok(proxy_data_message) => proxy_data_message,
                    Err(e) => {
                        error!("Fail to generate proxy data message because of error: {e:?}");
                        return;
                    }
                };
                if let Err(e) = agent_connection_write.send(proxy_data_message).await {
                    error!("Transport [{transport_id}] fail to send agent recv buffer data to destination because of error: {e:?}");
                    return;
                };
            }
        });
    }

    /// Read the agent data to receive buffer
    fn start_receive_dest_message(
        transport_id: String,
        mut dest_recv_buf_tx: Sender<Bytes>,
        mut dest_connection_read: DestConnectionRead,
    ) {
        tokio::spawn(async move {
            loop {
                let dest_message = match dest_connection_read.next().await {
                    Some(Ok(dest_message)) => dest_message,
                    Some(Err(e)) => {
                        error!(
                            "Transport [{transport_id}] fail to read dest connection because of error: {e:?}"
                        );
                        return;
                    }
                    None => {
                        return;
                    }
                };
                if let Err(e) = dest_recv_buf_tx.send(dest_message.freeze()).await {
                    error!("Transport [{transport_id}] fail to send dest data to relay because of error: {e:?}");
                    return;
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
            while let Some(agent_data_to_send) = agent_recv_buf_rx.next().await {
                if let Err(e) = dest_connection_write.send(agent_data_to_send).await {
                    error!("Transport [{transport_id}] fail to send agent recv buffer data to destination because of error: {e:?}");
                    return;
                };
            }
        });
    }

    /// Read the agent data to receive buffer
    fn start_receive_agent_message(
        transport_id: String,
        mut agent_recv_buf_tx: Sender<Bytes>,
        mut agent_connection_read: AgentConnectionRead<T>,
    ) {
        tokio::spawn(async move {
            loop {
                let agent_wrapped_message = match agent_connection_read.next().await {
                    Some(Ok(agent_wrapper_message)) => agent_wrapper_message,
                    Some(Err(e)) => {
                        error!(
                            "Transport [{transport_id}] fail to read agent connection because of error: {e:?}"
                        );
                        return;
                    }
                    None => {
                        return;
                    }
                };

                let UnwrappedAgentTcpPayload {
                    payload: agent_tcp_payload,
                    ..
                } = match unwrap_agent_tcp_payload(agent_wrapped_message) {
                    Ok(agent_tcp_payload) => agent_tcp_payload,
                    Err(e) => {
                        error!("Fail to unwrap agent tcp message because of error: {e:?}");
                        return;
                    }
                };
                let AgentTcpPayload::Data { data, .. } = agent_tcp_payload else {
                    error!("Incoming message is not a Data message, the transport [{transport_id}] in invalid status.");
                    return;
                };
                if let Err(e) = agent_recv_buf_tx.send(data).await {
                    error!("Transport [{transport_id}] fail to send agent data to relay because of error: {e:?}");
                    return;
                };
            }
        });
    }
}
