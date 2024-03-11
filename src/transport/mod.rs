mod tcp;
mod udp;

use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use ppaass_crypto::random_32_bytes;

use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use ppaass_protocol::message::{payload::tcp::AgentTcpPayload, PpaassProxyMessage};
use ppaass_protocol::message::{
    payload::udp::AgentUdpPayload, values::encryption::PpaassMessagePayloadEncryption,
};
use ppaass_protocol::message::{PpaassAgentMessage, PpaassAgentMessagePayload};
use ppaass_protocol::{
    generator::PpaassMessageGenerator,
    message::{payload::tcp::ProxyTcpInitResult, values::address::PpaassUnifiedAddress},
};
use pretty_hex::pretty_hex;
use scopeguard::ScopeGuard;
use std::sync::Arc;
use std::{net::SocketAddr, sync::atomic::AtomicU64};
use std::{net::ToSocketAddrs, time::Duration};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tokio_io_timeout::TimeoutStream;
use tokio_util::codec::{BytesCodec, Framed};

use tracing::{debug, error, trace};

use uuid::Uuid;

use crate::codec::PpaassAgentEdgeCodec;
use crate::crypto::ProxyServerPayloadEncryptionSelector;

use crate::trace::TraceSubscriber;
use crate::{config::PROXY_CONFIG, crypto::RSA_CRYPTO, error::ProxyServerError};

const MAX_UDP_PACKET_SIZE: usize = 65535;
const LOCAL_UDP_BIND_ADDR: &str = "0.0.0.0:0";
pub(crate) trait TransportState {}

/// The state for initial
pub(crate) struct InitState;

impl TransportState for InitState {}

/// The state for agent connected
pub(crate) enum AgentAcceptedState {
    Tcp {
        user_token: String,
        agent_connection_read: SplitStream<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec>>,
        agent_connection_write:
            SplitSink<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec>, PpaassProxyMessage>,
        dst_address: PpaassUnifiedAddress,
        src_address: PpaassUnifiedAddress,
        payload_encryption: PpaassMessagePayloadEncryption,
        agent_address: PpaassUnifiedAddress,
    },
    Udp {
        user_token: String,
        agent_connection_read: SplitStream<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec>>,
        agent_connection_write:
            SplitSink<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec>, PpaassProxyMessage>,
        dst_address: PpaassUnifiedAddress,
        src_address: PpaassUnifiedAddress,
        payload_encryption: PpaassMessagePayloadEncryption,
        need_response: bool,
        agent_address: PpaassUnifiedAddress,
    },
}

impl TransportState for AgentAcceptedState {}

pub(crate) enum DestConnectedState {
    Tcp {
        user_token: String,
        agent_connection_read: SplitStream<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec>>,
        agent_connection_write:
            SplitSink<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec>, PpaassProxyMessage>,
        dst_address: PpaassUnifiedAddress,
        src_address: PpaassUnifiedAddress,
        payload_encryption: PpaassMessagePayloadEncryption,
        agent_address: PpaassUnifiedAddress,
        dst_connection: Framed<TimeoutStream<TcpStream>, BytesCodec>,
    },
    Udp {
        user_token: String,
        agent_connection_read: SplitStream<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec>>,
        agent_connection_write:
            SplitSink<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec>, PpaassProxyMessage>,
        dst_address: PpaassUnifiedAddress,
        src_address: PpaassUnifiedAddress,
        payload_encryption: PpaassMessagePayloadEncryption,
        need_response: bool,
        agent_address: PpaassUnifiedAddress,
        dst_udp_socket: UdpSocket,
    },
}

impl TransportState for DestConnectedState {}

pub(crate) struct ClosedState {}

impl TransportState for ClosedState {}

pub(crate) struct Transport<S: TransportState> {
    transport_id: String,
    state: S,
}

impl<S: TransportState> Transport<S> {
    pub(crate) fn get_id(&self) -> &str {
        &self.transport_id
    }
}

impl Transport<InitState> {
    /// Accept the agent connection
    pub(crate) fn new() -> Transport<InitState> {
        let transport_id = Uuid::new_v4().to_string();
        debug!("Create transport [{transport_id}]");
        Self {
            transport_id,
            state: InitState,
        }
    }

    /// Accept the agent connection
    pub(crate) async fn accept_agent_connection(
        self,
        agent_address: PpaassUnifiedAddress,
        agent_tcp_stream: TcpStream,
    ) -> Result<Transport<AgentAcceptedState>, ProxyServerError> {
        let transport_id = self.transport_id;
        let mut agent_tcp_stream = TimeoutStream::new(agent_tcp_stream);
        agent_tcp_stream.set_read_timeout(Some(Duration::from_secs(120)));
        agent_tcp_stream.set_write_timeout(Some(Duration::from_secs(120)));
        let agent_connection = Framed::with_capacity(
            agent_tcp_stream,
            PpaassAgentEdgeCodec::new(PROXY_CONFIG.get_compress(), RSA_CRYPTO.clone()),
            PROXY_CONFIG.get_agent_connection_codec_framed_buffer_size(),
        );
        let (agent_connection_write, mut agent_connection_read) = agent_connection.split();
        let agent_message = match agent_connection_read.next().await {
            Some(agent_message) => agent_message?,
            None => {
                return Err(ProxyServerError::Other(format!(
                    "Transport {transport_id} fail to accept agent connection because of exhausted."
                )));
            }
        };
        let PpaassAgentMessage {
            user_token,
            message_id,
            payload,
            ..
        } = agent_message;
        let payload_encryption =
            ProxyServerPayloadEncryptionSelector::select(&user_token, Some(random_32_bytes()));

        match payload {
            PpaassAgentMessagePayload::Tcp(payload_content) => {
                let AgentTcpPayload::Init {
                    dst_address,
                    src_address,
                } = payload_content
                else {
                    error!("Transport [{transport_id}] expect to receive tcp init message but it is not: {payload_content:?}");
                    return Err(ProxyServerError::Other(format!(
                        "Transport [{transport_id}] expect to receive tcp init message but it is not"
                    )));
                };
                debug!("Transport [{transport_id}] receive tcp init message[{message_id}], src address: {src_address}, dst address: {dst_address}");
                Ok(Transport {
                    transport_id,
                    state: AgentAcceptedState::Tcp {
                        user_token,
                        agent_connection_read,
                        agent_connection_write,
                        dst_address,
                        src_address,
                        payload_encryption,
                        agent_address,
                    },
                })
            }
            PpaassAgentMessagePayload::Udp(payload_content) => {
                let AgentUdpPayload {
                    src_address,
                    dst_address,
                    data: udp_data,
                    need_response,
                    ..
                } = payload_content;
                debug!("Transport [{transport_id}] receive udp data message[{message_id}], src address: {src_address}, dst address: {dst_address}");
                trace!(
                    "Transport [{transport_id}] receive udp data: {}",
                    pretty_hex(&udp_data)
                );
                // Udp transport will block the thread and continue to
                // handle the agent connection in a loop
                Ok(Transport {
                    transport_id,
                    state: AgentAcceptedState::Udp {
                        user_token,
                        agent_connection_read,
                        agent_connection_write,
                        dst_address,
                        src_address,
                        payload_encryption,
                        need_response,
                        agent_address,
                    },
                })
            }
        }
    }
}

impl Transport<AgentAcceptedState> {
    pub(crate) async fn connect_dest(
        self,
    ) -> Result<Transport<DestConnectedState>, ProxyServerError> {
        let state = self.state;
        let transport_id = self.transport_id;
        match state {
            AgentAcceptedState::Tcp {
                agent_connection_read,
                mut agent_connection_write,
                dst_address,
                src_address,
                payload_encryption,
                agent_address,
                user_token,
            } => {
                let dst_socket_address =
                    dst_address.to_socket_addrs()?.collect::<Vec<SocketAddr>>();
                let dst_tcp_stream = match timeout(
                    Duration::from_secs(PROXY_CONFIG.get_dst_connect_timeout()),
                    TcpStream::connect(dst_socket_address.as_slice()),
                )
                .await
                {
                    Err(_) => {
                        error!(
                    "Transport {transport_id} connect to tcp destination [{dst_address}] timeout in [{}] seconds.",
                    PROXY_CONFIG.get_dst_connect_timeout()
                );
                        return Err(ProxyServerError::Other(format!(
                    "Transport {transport_id} connect to tcp destination [{dst_address}] timeout in [{}] seconds.",
                    PROXY_CONFIG.get_dst_connect_timeout()
                )));
                    }
                    Ok(Ok(dst_tcp_stream)) => dst_tcp_stream,
                    Ok(Err(e)) => {
                        error!("Transport {transport_id} connect to tcp destination [{dst_address}] fail because of error: {e:?}");
                        return Err(ProxyServerError::StdIo(e));
                    }
                };

                dst_tcp_stream.set_nodelay(true)?;
                dst_tcp_stream.set_linger(None)?;
                let mut dst_tcp_stream = TimeoutStream::new(dst_tcp_stream);
                dst_tcp_stream.set_read_timeout(Some(Duration::from_secs(120)));
                dst_tcp_stream.set_write_timeout(Some(Duration::from_secs(120)));
                let dst_connection = Framed::new(dst_tcp_stream, BytesCodec::new());

                let tcp_init_success_message =
                    PpaassMessageGenerator::generate_proxy_tcp_init_message(
                        user_token.clone(),
                        src_address.clone(),
                        dst_address.clone(),
                        payload_encryption.clone(),
                        ProxyTcpInitResult::Success(transport_id.clone()),
                    )?;
                agent_connection_write
                    .send(tcp_init_success_message)
                    .await?;
                Ok(Transport {
                    transport_id,
                    state: DestConnectedState::Tcp {
                        user_token,
                        agent_connection_read,
                        agent_connection_write,
                        dst_address,
                        src_address,
                        payload_encryption,
                        agent_address,
                        dst_connection,
                    },
                })
            }
            AgentAcceptedState::Udp {
                user_token,
                agent_connection_read,
                mut agent_connection_write,
                dst_address,
                src_address,
                payload_encryption,
                need_response,
                agent_address,
            } => {
                let dst_udp_socket = UdpSocket::bind(LOCAL_UDP_BIND_ADDR).await?;
                let dst_socket_addrs = dst_address.to_socket_addrs()?;
                let dst_socket_addrs = dst_socket_addrs.collect::<Vec<SocketAddr>>();
                match timeout(
                    Duration::from_secs(PROXY_CONFIG.get_dst_udp_connect_timeout()),
                    dst_udp_socket.connect(dst_socket_addrs.as_slice()),
                )
                .await
                {
                    Err(_) => {
                        error!(
                    "Transport [{transport_id}] connect to destination udp socket [{dst_address}] timeout in [{}] seconds.",
                    PROXY_CONFIG.get_dst_udp_connect_timeout()
                );
                        if let Err(e) = agent_connection_write.close().await {
                            error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
                        };
                        return Err(ProxyServerError::Other(format!(
                    "Transport [{transport_id}] connect to destination udp socket [{dst_address}] timeout in [{}] seconds.",
                    PROXY_CONFIG.get_dst_udp_connect_timeout()
                )));
                    }
                    Ok(Ok(())) => {
                        debug!("Transport [{transport_id}] connect to destination udp socket [{dst_address}] success.");
                    }
                    Ok(Err(e)) => {
                        error!("Transport [{transport_id}] connect to destination udp socket [{dst_address}] fail because of error: {e:?}");
                        if let Err(e) = agent_connection_write.close().await {
                            error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
                        };
                        return Err(ProxyServerError::StdIo(e));
                    }
                };

                Ok(Transport {
                    transport_id,
                    state: DestConnectedState::Udp {
                        user_token,
                        agent_connection_read,
                        agent_connection_write,
                        dst_address,
                        src_address,
                        payload_encryption,
                        need_response,
                        agent_address,
                        dst_udp_socket,
                    },
                })
            }
        }
    }
}

impl Transport<DestConnectedState> {
    pub(crate) async fn relay<
        DF: FnOnce((String, Arc<TraceSubscriber>, Arc<AtomicU64>)) + Send + 'static,
    >(
        self,
        transport_number_scopeguard: ScopeGuard<(String, Arc<TraceSubscriber>, Arc<AtomicU64>), DF>,
    ) -> Result<Transport<ClosedState>, ProxyServerError> {
        //Read the first message from agent connection
        let transport_id = self.transport_id;
        let state = self.state;
        match state {
            DestConnectedState::Tcp {
                user_token,
                agent_connection_read,
                agent_connection_write,
                dst_address,
                src_address,
                payload_encryption,
                agent_address,
                dst_connection,
            } => todo!(),
            DestConnectedState::Udp {
                user_token,
                agent_connection_read,
                agent_connection_write,
                dst_address,
                src_address,
                payload_encryption,
                need_response,
                agent_address,
                dst_udp_socket,
            } => todo!(),
        }
    }
}
