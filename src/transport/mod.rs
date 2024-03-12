mod udp;

use bytes::{BufMut, Bytes, BytesMut};
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

use std::net::SocketAddr;
use std::{net::ToSocketAddrs, time::Duration};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tokio_io_timeout::TimeoutStream;
use tokio_stream::StreamExt as TokioStreamExt;
use tokio_util::codec::{BytesCodec, Framed};

use tracing::{debug, error, trace};

use uuid::Uuid;

use crate::codec::PpaassAgentEdgeCodec;
use crate::crypto::ProxyServerPayloadEncryptionSelector;

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
        udp_data: Bytes,
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
        udp_data: Bytes,
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
        let agent_message = match StreamExt::next(&mut agent_connection_read).await {
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
                        udp_data,
                    },
                })
            }
        }
    }
}

/// When transport in agent accepted state, it can connect to destination
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
                udp_data,
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
                        error!("Transport [{transport_id}] connect to destination udp socket [{dst_address}] timeout in [{}] seconds.",PROXY_CONFIG.get_dst_udp_connect_timeout());
                        if let Err(e) = agent_connection_write.close().await {
                            error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
                        };
                        return Err(ProxyServerError::Other(format!("Transport [{transport_id}] connect to destination udp socket [{dst_address}] timeout in [{}] seconds.",PROXY_CONFIG.get_dst_udp_connect_timeout())));
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
                        udp_data,
                    },
                })
            }
        }
    }
}

/// When transport in destination connected state, it can start relay.
impl Transport<DestConnectedState> {
    /// Unwrap the ppaass agent message to raw data
    fn unwrap_to_raw_tcp_data(message: PpaassAgentMessage) -> Result<Bytes, ProxyServerError> {
        let PpaassAgentMessage {
            payload: PpaassAgentMessagePayload::Tcp(AgentTcpPayload::Data { content }),
            ..
        } = message
        else {
            return Err(ProxyServerError::Other(format!(
                "Fail to unwrap raw data from agent message because of invalid payload type: {message:?}"
            )));
        };
        Ok(content)
    }

    pub(crate) async fn relay(self) -> Result<(), ProxyServerError> {
        //Read the first message from agent connection
        let transport_id = self.transport_id;
        let state = self.state;
        match state {
            DestConnectedState::Tcp {
                user_token,
                agent_connection_read,
                mut agent_connection_write,
                dst_address,
                payload_encryption,
                dst_connection,
                ..
            } => {
                let (mut dst_connection_write, dst_connection_read) = dst_connection.split();
                {
                    let dst_address = dst_address.clone();
                    let transport_id = transport_id.clone();
                    tokio::spawn(async move {
                        let agent_connection_read = TokioStreamExt::fuse(agent_connection_read);
                        if let Err(e) =
                            TokioStreamExt::map_while(agent_connection_read, |agent_message| {
                                let agent_message = agent_message.ok()?;
                                let data = Self::unwrap_to_raw_tcp_data(agent_message).ok()?;
                                Some(Ok(BytesMut::from_iter(data)))
                            })
                            .forward(&mut dst_connection_write)
                            .await
                        {
                            error!("Transport [{transport_id}] error happen when relay tcp data from agent to destination [{dst_address}]: {e:?}");
                        }
                        if let Err(e) = dst_connection_write.close().await {
                            error!("Transport [{transport_id}] fail to close destination connection [{dst_address}] because of error: {e:?}");
                        };
                    });
                }

                tokio::spawn(async move {
                    let dst_connection_read = TokioStreamExt::fuse(dst_connection_read);
                    if let Err(e) =
                        TokioStreamExt::map_while(dst_connection_read, move |dst_message| {
                            let dst_message = dst_message.ok()?;
                            let tcp_data_message =
                                PpaassMessageGenerator::generate_proxy_tcp_data_message(
                                    user_token.clone(),
                                    payload_encryption.clone(),
                                    dst_message.freeze(),
                                )
                                .ok()?;
                            Some(Ok(tcp_data_message))
                        })
                        .forward(&mut agent_connection_write)
                        .await
                    {
                        error!("Transport [{transport_id}] error happen when relay tcp data from destination [{dst_address}] to agent: {e:?}", );
                    }
                    if let Err(e) = agent_connection_write.close().await {
                        error!("Transport [{transport_id}] fail to close agent connection because of error: {e:?}");
                    };
                });
                Ok(())
            }
            DestConnectedState::Udp {
                user_token,
                mut agent_connection_write,
                dst_address,
                src_address,
                payload_encryption,
                need_response,
                dst_udp_socket,
                udp_data,
                ..
            } => {
                if let Err(e) = dst_udp_socket.send(&udp_data).await {
                    error!("Transport [{transport_id}] fail to relay agent udp data to destination udp socket [{dst_address}] because of error: {e:?}");
                    if let Err(e) = agent_connection_write.close().await {
                        error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
                    };
                    return Err(ProxyServerError::StdIo(e));
                };
                if !need_response {
                    if let Err(e) = agent_connection_write.close().await {
                        error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
                    };
                    return Ok(());
                }
                tokio::spawn(async move {
                    let mut udp_data = BytesMut::new();
                    loop {
                        let mut udp_recv_buf = [0u8; MAX_UDP_PACKET_SIZE];
                        let (udp_recv_buf, size) = match timeout(
                            Duration::from_secs(PROXY_CONFIG.get_dst_udp_recv_timeout()),
                            dst_udp_socket.recv(&mut udp_recv_buf),
                        )
                        .await
                        {
                            Err(_) => {
                                debug!(
                        "Transport [{transport_id}] receive data from destination udp socket [{dst_address}] timeout in [{}] seconds.",
                        PROXY_CONFIG.get_dst_udp_recv_timeout()
                    );
                                if let Err(e) = agent_connection_write.close().await {
                                    error!(
                            "Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}"
                        );
                                };
                                return Err(ProxyServerError::Other(format!(
                            "Transport [{transport_id}] receive data from destination udp socket [{dst_address}] timeout in [{}] seconds.",
                            PROXY_CONFIG.get_dst_udp_recv_timeout()
                        )));
                            }
                            Ok(Ok(0)) => {
                                debug!("Transport [{transport_id}] receive all data from destination udp socket [{dst_address}], current udp packet size: {}, last receive data size is zero",udp_data.len());
                                break;
                            }
                            Ok(size) => {
                                let size = size?;
                                (&udp_recv_buf[..size], size)
                            }
                        };
                        udp_data.put(udp_recv_buf);
                        if size < MAX_UDP_PACKET_SIZE {
                            debug!(
                    "Transport [{transport_id}] receive all data from destination udp socket [{dst_address}], current udp packet size: {}, last receive data size is: {size}",
                    udp_data.len()
                );
                            break;
                        }
                    }
                    if udp_data.is_empty() {
                        if let Err(e) = agent_connection_write.close().await {
                            error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
                        };
                        return Ok(());
                    }
                    let udp_data_message = PpaassMessageGenerator::generate_proxy_udp_data_message(
                        user_token.clone(),
                        payload_encryption,
                        src_address.clone(),
                        dst_address.clone(),
                        udp_data.freeze(),
                    )?;
                    if let Err(e) = agent_connection_write.send(udp_data_message).await {
                        error!("Transport [{transport_id}] fail to relay destination udp socket data [{dst_address}] udp data to agent because of error: {e:?}");
                    };
                    if let Err(e) = agent_connection_write.close().await {
                        error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
                    };
                    Ok(())
                });
                Ok(())
            }
        }
    }
}
