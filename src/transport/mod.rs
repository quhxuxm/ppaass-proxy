mod state;

use bytes::{BufMut, Bytes, BytesMut};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use ppaass_crypto::{crypto::RsaCryptoFetcher, random_32_bytes};

use ppaass_protocol::message::payload::udp::AgentUdpPayload;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use ppaass_protocol::message::{payload::tcp::AgentTcpPayload, PpaassProxyMessage};
use ppaass_protocol::message::{PpaassAgentMessage, PpaassAgentMessagePayload};
use ppaass_protocol::{
    generator::PpaassMessageGenerator, message::payload::tcp::ProxyTcpInitResult,
};
use pretty_hex::pretty_hex;

use std::{fmt::Display, net::SocketAddr};
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

use crate::crypto::ProxyServerPayloadEncryptionSelector;
use crate::{codec::PpaassAgentEdgeCodec, config::ProxyConfig};

use crate::error::ProxyServerError;

pub(crate) use state::AgentAcceptedState;
pub(crate) use state::DestConnectedState;
pub(crate) use state::InitState;

use self::state::{RelayState, TransportState};

/// The agent connection read part type
pub(crate) type AgentConnectionRead<F> =
    SplitStream<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec<F>>>;

/// The agent connection write part type
pub(crate) type AgentConnectionWrite<F> =
    SplitSink<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec<F>>, PpaassProxyMessage>;

/// The max udp packet size
const MAX_UDP_PACKET_SIZE: usize = 65535;

/// The udp dind address
const LOCAL_UDP_BIND_ADDR: &str = "0.0.0.0:0";

/// The transport between agent and destination
pub(crate) struct Transport<'config, 'crypto, S, F>
where
    S: TransportState + Display,
    F: RsaCryptoFetcher + Clone + Send + Sync,
{
    /// The id of the transport
    transport_id: String,
    /// The state of the transport
    state: S,
    /// The configuration of the proxy
    config: &'config ProxyConfig,
    rsa_crypto_fetcher: &'crypto F,
}

impl<'config, 'crypto, S, F> Transport<'config, 'crypto, S, F>
where
    S: TransportState + Display,
    F: RsaCryptoFetcher + Clone + Send + Sync,
{
    /// Get the id of the transport
    pub(crate) fn get_id(&self) -> &str {
        &self.transport_id
    }

    /// Get the state of the transport
    pub(crate) fn get_state(&self) -> &S {
        &self.state
    }
}

impl<'config, 'crypto, F> Transport<'config, 'crypto, InitState, F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync,
{
    /// Create a new transport
    pub(crate) fn new(
        config: &'config ProxyConfig,
        rsa_crypto_fetcher: &'crypto F,
    ) -> Transport<'config, 'crypto, InitState, F> {
        Self {
            transport_id: Uuid::new_v4().to_string(),
            state: InitState,
            config,
            rsa_crypto_fetcher,
        }
    }

    /// Accept the agent connection
    pub(crate) async fn accept_agent_connection(
        self,
        agent_tcp_stream: TcpStream,
    ) -> Result<Transport<'config, 'crypto, AgentAcceptedState<'crypto, F>, F>, ProxyServerError>
    {
        let transport_id = self.transport_id;
        let mut agent_tcp_stream = TimeoutStream::new(agent_tcp_stream);
        agent_tcp_stream.set_read_timeout(Some(Duration::from_secs(
            self.config.get_agent_connection_read_timeout(),
        )));
        agent_tcp_stream.set_write_timeout(Some(Duration::from_secs(
            self.config.get_agent_connection_write_timeout(),
        )));
        let agent_connection = Framed::with_capacity(
            agent_tcp_stream,
            PpaassAgentEdgeCodec::new(self.config.get_compress(), self.rsa_crypto_fetcher),
            self.config.get_agent_connection_codec_framed_buffer_size(),
        );
        let (agent_connection_write, mut agent_connection_read) = agent_connection.split();
        let agent_message =
            StreamExt::next(&mut agent_connection_read)
                .await
                .ok_or(ProxyServerError::Other(format!(
                "Transport [{transport_id}] fail to accept agent connection because of exhausted."
            )))?.map_err(|e|{
                error!("Transport [{transport_id}] fail to read data from agent connection because of error: {e:?}");
                e
            })?;
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
                    return Err(ProxyServerError::Other(format!(
                        "Transport [{transport_id}] expect to receive tcp init message but it is not: {payload_content:?}"
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
                    },
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
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
                        agent_connection_write,
                        dst_address,
                        src_address,
                        payload_encryption,
                        need_response,
                        udp_data,
                    },
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                })
            }
        }
    }
}

/// When transport in agent accepted state, it can connect to destination
impl<'config, 'crypto, F> Transport<'config, 'crypto, AgentAcceptedState<'crypto, F>, F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync,
{
    /// Connect the transport to destination
    pub(crate) async fn connect_to_destination(
        self,
    ) -> Result<Transport<'config, 'crypto, DestConnectedState<'crypto, F>, F>, ProxyServerError>
    {
        let state = self.state;
        let transport_id = self.transport_id;
        match state {
            AgentAcceptedState::Tcp {
                agent_connection_read,
                mut agent_connection_write,
                dst_address,
                src_address,
                payload_encryption,
                user_token,
            } => {
                let dst_socket_address =
                    dst_address.to_socket_addrs()?.collect::<Vec<SocketAddr>>();
                let dst_tcp_stream = timeout(
                    Duration::from_secs(self.config.get_dst_tcp_connect_timeout()),
                    TcpStream::connect(dst_socket_address.as_slice()),
                )
                .await.map_err(|_|ProxyServerError::Other(format!(
                    "Transport [{transport_id}] connect to tcp destination [{dst_address}] timeout in [{}] seconds.",
                    self.config.get_dst_tcp_connect_timeout()
                )))?.map_err(|e|{
                    error!("Transport [{transport_id}] connect to tcp destination [{dst_address}] fail because of error: {e:?}");
                    ProxyServerError::StdIo(e)
                })?;

                dst_tcp_stream.set_nodelay(true)?;
                dst_tcp_stream.set_linger(None)?;
                let mut dst_tcp_stream = TimeoutStream::new(dst_tcp_stream);
                dst_tcp_stream.set_read_timeout(Some(Duration::from_secs(
                    self.config.get_dst_tcp_read_timeout(),
                )));
                dst_tcp_stream.set_write_timeout(Some(Duration::from_secs(
                    self.config.get_dst_tcp_write_timeout(),
                )));
                let dst_connection = Framed::with_capacity(
                    dst_tcp_stream,
                    BytesCodec::new(),
                    self.config.get_dst_connection_codec_framed_buffer_size(),
                );
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
                        payload_encryption,
                        dst_connection,
                    },
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                })
            }
            AgentAcceptedState::Udp {
                user_token,
                dst_address,
                src_address,
                payload_encryption,
                need_response,
                udp_data,
                agent_connection_write,
            } => {
                let dst_udp_socket = UdpSocket::bind(LOCAL_UDP_BIND_ADDR).await?;
                let dst_socket_addrs = dst_address.to_socket_addrs()?;
                let dst_socket_addrs = dst_socket_addrs.collect::<Vec<SocketAddr>>();
                timeout(
                    Duration::from_secs(self.config.get_dst_udp_connect_timeout()),
                    dst_udp_socket.connect(dst_socket_addrs.as_slice()),
                )
                .await.map_err(|_|{
                    ProxyServerError::Other(format!("Transport [{transport_id}] connect to destination udp socket [{dst_address}] timeout in [{}] seconds.",self.config.get_dst_udp_connect_timeout()))
                })?.map_err(|e|{
                    error!("Transport [{transport_id}] connect to destination udp socket [{dst_address}] fail because of error: {e:?}");
                    ProxyServerError::StdIo(e)
                })?;
                Ok(Transport {
                    transport_id,
                    state: DestConnectedState::Udp {
                        user_token,
                        agent_connection_write,
                        dst_address,
                        src_address,
                        payload_encryption,
                        need_response,
                        dst_udp_socket,
                        udp_data,
                    },
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                })
            }
        }
    }
}

/// When transport in destination connected state, it can start relay.
impl<'config, 'crypto, F> Transport<'config, 'crypto, DestConnectedState<'crypto, F>, F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync,
    'crypto: 'static,
{
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

    /// Relay the data through the transport between agent and destination
    pub(crate) async fn relay(
        self,
    ) -> Result<Transport<'config, 'crypto, RelayState, F>, ProxyServerError> {
        //Read the first message from agent connection
        let transport_id = self.transport_id;
        let state = self.state;
        match state {
            DestConnectedState::Tcp {
                user_token,
                agent_connection_read,
                mut agent_connection_write,
                payload_encryption,
                dst_connection,
                ..
            } => {
                let (mut dst_connection_write, dst_connection_read) = dst_connection.split();
                {
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
                            error!("Transport [{transport_id}] error happen when relay tcp data from agent to destination: {e:?}");
                        }
                    });
                }

                {
                    let transport_id = transport_id.clone();
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
                            error!("Transport [{transport_id}] error happen when relay tcp data from destination to agent: {e:?}", );
                        }
                    });
                }
                Ok(Transport {
                    transport_id,
                    state: RelayState,
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                })
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
                dst_udp_socket.send(&udp_data).await .map_err(|e|{
                    error!("Transport [{transport_id}] fail to relay agent udp data to destination udp socket [{dst_address}] because of error: {e:?}");
                    ProxyServerError::StdIo(e)
                })?;
                if !need_response {
                    return Ok(Transport {
                        transport_id,
                        state: RelayState,
                        config: self.config,
                        rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                    });
                }
                {
                    let transport_id = transport_id.clone();
                    let dst_udp_recv_timeout = self.config.get_dst_udp_recv_timeout();
                    tokio::spawn(async move {
                        let mut udp_data = BytesMut::new();
                        loop {
                            let mut udp_recv_buf = [0u8; MAX_UDP_PACKET_SIZE];
                            let (udp_recv_buf, size) = match timeout(
                                Duration::from_secs(dst_udp_recv_timeout),
                                dst_udp_socket.recv(&mut udp_recv_buf),
                            )
                            .await
                            {
                                Err(_) => {
                                    return Err(ProxyServerError::Other(format!("Transport [{transport_id}] receive data from destination udp socket [{dst_address}] timeout in [{dst_udp_recv_timeout}] seconds.")));
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
                                debug!("Transport [{transport_id}] receive all data from destination udp socket [{dst_address}], current udp packet size: {}, last receive data size is: {size}",udp_data.len());
                                break;
                            }
                        }
                        if udp_data.is_empty() {
                            return Ok(());
                        }
                        let udp_data_message =
                            PpaassMessageGenerator::generate_proxy_udp_data_message(
                                user_token.clone(),
                                payload_encryption,
                                src_address.clone(),
                                dst_address.clone(),
                                udp_data.freeze(),
                            )?;
                        if let Err(e) = agent_connection_write.send(udp_data_message).await {
                            error!("Transport [{transport_id}] fail to relay destination udp socket data [{dst_address}] udp data to agent because of error: {e:?}");
                        };
                        Ok(())
                    });
                }
                Ok(Transport {
                    transport_id,
                    state: RelayState,
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                })
            }
        }
    }
}
