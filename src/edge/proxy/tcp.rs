use anyhow::Result;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream, StreamExt};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::SinkExt;
use log::{debug, error};
use pin_project::pin_project;

use ppaass_protocol::message::proxy::{
    CloseTunnelCommand, InitTunnelResult, ProxyMessage, ProxyMessagePayload, RelayData,
};

use ppaass_protocol::values::address::NetAddress;
use ppaass_protocol::values::security::{Encryption, SecureInfo};
use ppaass_protocol::values::tunnel::{Tunnel, TunnelType};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_util::codec::{BytesCodec, Framed};

use uuid::Uuid;

use crate::util::random_32_bytes;

use crate::error::ProxyError;

/// Define the simple alias for the read part
type DstConnectionRead = SplitStream<DstTcpConnection<TcpStream>>;

/// The destination connection framed with BytesCodec
#[pin_project]
struct DstTcpConnection<T>
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

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        let this = self.project();
        Sink::<Bytes>::poll_ready(this.inner, cx).map_err(ProxyError::Io)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> std::result::Result<(), Self::Error> {
        let this = self.project();
        Sink::<Bytes>::start_send(this.inner, item).map_err(ProxyError::Io)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        let this = self.project();
        Sink::<Bytes>::poll_flush(this.inner, cx).map_err(ProxyError::Io)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        let this = self.project();
        Sink::<Bytes>::poll_close(this.inner, cx).map_err(ProxyError::Io)
    }
}

/// Implemente the Stream trait for DstTcpConnection object
impl<T> Stream for DstTcpConnection<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    type Item = std::result::Result<BytesMut, ProxyError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx).map_err(ProxyError::Io)
    }
}

pub(crate) struct TcpProxyEdge {
    agent_edge_id: String,
    proxy_edge_id: String,
    src_address: NetAddress,
    dst_address: NetAddress,
    user_token: String,
    agent_edge_output_tx: UnboundedSender<ProxyMessage>,
    proxy_edge_relay_rx: UnboundedReceiver<Bytes>,
    dst_tcp_connection: Option<DstTcpConnection<TcpStream>>,
}

impl TcpProxyEdge {
    pub fn new(
        agent_edge_id: String,
        proxy_edge_id: String,
        src_address: NetAddress,
        dst_address: NetAddress,
        user_token: String,
        proxy_edge_relay_rx: UnboundedReceiver<Bytes>,
        agent_edge_output_tx: UnboundedSender<ProxyMessage>,
    ) -> TcpProxyEdge {
        Self {
            agent_edge_id,
            proxy_edge_id,
            src_address,
            dst_address,
            user_token,
            proxy_edge_relay_rx,
            dst_tcp_connection: None,
            agent_edge_output_tx,
        }
    }

    pub async fn connect(&mut self) -> Result<(), ProxyError> {
        debug!(
            "Transport [{}] going to connect destination: {:?}",
            self.proxy_edge_id, self.dst_address
        );
        let dst_tcp_stream = match &self.dst_address {
            NetAddress::Ip(ip_addr) => TcpStream::connect(ip_addr).await?,
            NetAddress::Domain { host, port } => TcpStream::connect((host.as_ref(), *port)).await?,
        };

        debug!(
            "Transport [{}] success connect to destination: {:?}",
            self.proxy_edge_id, self.dst_address
        );

        // Generate success proxy init response message
        let tcp_init_success_result = ProxyMessage {
            message_id: Uuid::new_v4().to_string(),
            secure_info: SecureInfo {
                user_token: self.user_token.clone(),
                encryption: Encryption::Aes(random_32_bytes()),
            },
            tunnel: Tunnel {
                agent_edge_id: self.agent_edge_id.clone(),
                proxy_edge_id: Some(self.proxy_edge_id.clone()),
                tunnel_type: TunnelType::Tcp,
            },
            payload: ProxyMessagePayload::InitTunnelResult(InitTunnelResult {
                src_address: self.src_address.clone(),
                dst_address: self.dst_address.clone(),
            }),
        };

        self.agent_edge_output_tx
            .send(tcp_init_success_result)
            .map_err(|e|ProxyError::Other(format!("Transport [{}] fail to send tcp init success response to agent connection output sender [{}] because of error: {e:?}", self.proxy_edge_id, self.agent_edge_id)))?;
        debug!(
            "Transport [{}] success send tcp init success response to agent through agent connection [{}]",
            self.proxy_edge_id,
            self.agent_edge_id
        );
        self.dst_tcp_connection = Some(DstTcpConnection::new(dst_tcp_stream, 65536));
        Ok(())
    }

    pub async fn exec(mut self) -> Result<(), ProxyError> {
        let proxy_edge_id = self.proxy_edge_id;
        let user_token = self.user_token;
        let Some(dst_tcp_connection) = self.dst_tcp_connection else {
            return Err(ProxyError::Other(format!(
                "Transport [{proxy_edge_id}] destination tcp connection still not initialized"
            )));
        };

        let (mut dst_tcp_connection_write, dst_tcp_connection_read) = dst_tcp_connection.split();
        Self::start_dst_relay_to_agent(
            proxy_edge_id,
            user_token,
            dst_tcp_connection_read,
            self.agent_edge_output_tx,
            self.agent_edge_id,
            self.src_address,
            self.dst_address,
        );
        while let Some(data) = self.proxy_edge_relay_rx.recv().await {
            dst_tcp_connection_write.send(data).await?;
        }
        Ok(())
    }

    fn start_dst_relay_to_agent(
        proxy_edge_id: String,
        user_token: String,
        mut dst_tcp_connection_read: DstConnectionRead,
        agent_edge_output_tx: UnboundedSender<ProxyMessage>,
        agent_edge_id: String,
        src_address: NetAddress,
        dst_address: NetAddress,
    ) {
        tokio::spawn(async move {
            loop {
                let dst_data = match dst_tcp_connection_read.next().await {
                    Some(Ok(dst_data)) => dst_data,
                    Some(Err(e)) => {
                        error!("Transport [{proxy_edge_id}] fail to read dest connection because of error: {e:?}");
                        return;
                    }
                    None => {
                        debug!("Transport [{proxy_edge_id}] complete to read destination data, send tcp close request to agent.");
                        let tcp_relay_data = ProxyMessage {
                            message_id: Uuid::new_v4().to_string(),
                            secure_info: SecureInfo {
                                user_token,
                                encryption: Encryption::Aes(random_32_bytes()),
                            },
                            tunnel: Tunnel {
                                agent_edge_id: agent_edge_id.clone(),
                                proxy_edge_id: Some(proxy_edge_id.clone()),
                                tunnel_type: TunnelType::Tcp,
                            },
                            payload: ProxyMessagePayload::CloseTunnelCommand(CloseTunnelCommand {
                                src_address: src_address.clone(),
                                dst_address: dst_address.clone(),
                            }),
                        };
                        if let Err(e) = agent_edge_output_tx.send(tcp_relay_data) {
                            error!("Transport [{proxy_edge_id}] fail to send tcp close to agent connection [{agent_edge_id}] because of error: {e:?}");
                            return;
                        };
                        return;
                    }
                };

                let tcp_relay_data = ProxyMessage {
                    message_id: Uuid::new_v4().to_string(),
                    secure_info: SecureInfo {
                        user_token: user_token.clone(),
                        encryption: Encryption::Aes(random_32_bytes()),
                    },
                    tunnel: Tunnel {
                        agent_edge_id: agent_edge_id.clone(),
                        proxy_edge_id: Some(proxy_edge_id.clone()),
                        tunnel_type: TunnelType::Tcp,
                    },
                    payload: ProxyMessagePayload::RelayData(RelayData {
                        src_address: src_address.clone(),
                        dst_address: dst_address.clone(),
                        data: dst_data.freeze(),
                    }),
                };

                if let Err(e) = agent_edge_output_tx.send(tcp_relay_data) {
                    error!("Transport [{proxy_edge_id}] fail to send wrapper message to agent tcp connection [{agent_edge_id}] because of error: {e:?}");
                    return;
                };
            }
        });
    }
}
