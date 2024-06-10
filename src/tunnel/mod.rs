use std::{fmt::Display, net::SocketAddr};
use std::{net::ToSocketAddrs, time::Duration};
use std::marker::PhantomData;
use std::sync::Arc;
use bytes::{Bytes, BytesMut};
use futures::{
    SinkExt,
    stream::{SplitSink, SplitStream}, StreamExt,
};
use ppaass_crypto::{crypto::RsaCryptoFetcher, random_32_bytes};
use ppaass_protocol::{
    generator::PpaassMessageGenerator, message::payload::tcp::ProxyTcpInitResult,
};
use ppaass_protocol::message::{payload::tcp::AgentTcpPayload, PpaassProxyMessage};
use ppaass_protocol::message::{PpaassAgentMessage, PpaassAgentMessagePayload};
use ppaass_protocol::message::payload::udp::AgentUdpPayload;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use pretty_hex::pretty_hex;
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tokio_io_timeout::TimeoutStream;
use tokio_stream::StreamExt as TokioStreamExt;
use tokio_tfo::TfoStream;
use tokio_util::codec::{BytesCodec, Framed};
use tracing::{debug, error, trace};
use uuid::Uuid;
pub use state::AgentAcceptedState;
pub use state::DestConnectedState;
pub use state::InitState;
use crate::{codec::PpaassAgentEdgeCodec, config::ProxyConfig};
use crate::crypto::ProxyServerPayloadEncryptionSelector;
use crate::error::ProxyServerError;
use self::state::{RelayState, TunnelState};
mod state;
/// The agent connection read part type
pub type AgentConnectionRead<F> =
    SplitStream<Framed<TimeoutStream<TfoStream>, PpaassAgentEdgeCodec<F>>>;
/// The agent connection write part type
pub type AgentConnectionWrite<F> =
    SplitSink<Framed<TimeoutStream<TfoStream>, PpaassAgentEdgeCodec<F>>, PpaassProxyMessage>;
/// The max udp packet size
const MAX_UDP_PACKET_SIZE: usize = 65535;
/// The udp bind address
const LOCAL_UDP_BIND_ADDR: &str = "0.0.0.0:0";
/// The tunnel between agent and destination
pub struct Tunnel<'config, 'crypto, S, F>
where
    S: TunnelState + Display,
    F: RsaCryptoFetcher + Clone + Send + Sync + 'crypto,
{
    /// The id of the tunnel
    tunnel_id: String,
    /// The state of the tunnel
    state: S,
    /// The configuration of the proxy
    config: &'config ProxyConfig,
    rsa_crypto_fetcher: F,
    _marker: &'crypto PhantomData<()>,
}
impl<'config, 'crypto, S, F> Tunnel<'config, 'crypto, S, F>
where
    S: TunnelState + Display,
    F: RsaCryptoFetcher + Clone + Send + Sync + 'crypto,
{
    /// Get the id of the tunnel
    pub fn get_id(&self) -> &str {
        &self.tunnel_id
    }
    /// Get the state of the tunnel
    pub fn get_state(&self) -> &S {
        &self.state
    }
}
impl<'config, 'crypto, F> Tunnel<'config, 'crypto, InitState, F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync + 'crypto,
{
    /// Create a new tunnel
    pub fn new(
        config: &'config ProxyConfig,
        rsa_crypto_fetcher: F,
    ) -> Tunnel<'config, 'crypto, InitState, F> {
        Self {
            tunnel_id: Uuid::new_v4().to_string(),
            state: InitState,
            config,
            rsa_crypto_fetcher,
            _marker: &PhantomData,
        }
    }
    /// Accept the agent connection
    pub async fn accept_agent_connection(
        self,
        agent_tcp_stream: TfoStream,
    ) -> Result<Tunnel<'config, 'crypto, AgentAcceptedState<'crypto, F>, F>, ProxyServerError> {
        let tunnel_id = self.tunnel_id;
        let mut agent_tcp_stream = TimeoutStream::new(agent_tcp_stream);
        agent_tcp_stream.set_read_timeout(Some(Duration::from_secs(
            self.config.agent_connection_read_timeout(),
        )));
        agent_tcp_stream.set_write_timeout(Some(Duration::from_secs(
            self.config.agent_connection_write_timeout(),
        )));
        let agent_connection = Framed::with_capacity(
            agent_tcp_stream,
            PpaassAgentEdgeCodec::new(self.config.compress(), self.rsa_crypto_fetcher.clone()),
            self.config.agent_connection_codec_framed_buffer_size(),
        );
        let (agent_connection_write, mut agent_connection_read) = agent_connection.split();
        let agent_message =
            StreamExt::next(&mut agent_connection_read)
                .await
                .ok_or(ProxyServerError::Other(format!(
                    "Tunnel [{tunnel_id}] fail to accept agent connection because of exhausted."
                )))?.map_err(|e| {
                error!("Tunnel [{tunnel_id}] fail to read data from agent connection because of error: {e:?}");
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
                            "Tunnel [{tunnel_id}] expect to receive tcp init message but it is not: {payload_content:?}"
                        )));
                };
                debug!("Tunnel [{tunnel_id}] receive tcp init message[{message_id}], src address: {src_address}, dst address: {dst_address}");
                Ok(Tunnel {
                    tunnel_id,
                    state: AgentAcceptedState::Tcp {
                        user_token,
                        agent_connection_read,
                        agent_connection_write,
                        dst_address,
                        src_address,
                        payload_encryption,
                        _marker: &PhantomData,
                    },
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                    _marker: &PhantomData,
                })
            }
            PpaassAgentMessagePayload::Udp(payload_content) => {
                let AgentUdpPayload {
                    src_address,
                    dst_address,
                    data: udp_data,
                } = payload_content;
                debug!("Tunnel [{tunnel_id}] receive udp data message[{message_id}], src address: {src_address}, dst address: {dst_address}");
                trace!(
                    "Tunnel [{tunnel_id}] receive udp data: {}",
                    pretty_hex(&udp_data)
                );
                // Udp tunnel will block the thread and continue to
                // handle the agent connection in a loop
                Ok(Tunnel {
                    tunnel_id,
                    state: AgentAcceptedState::Udp {
                        user_token,
                        agent_connection_write,
                        agent_connection_read,
                        dst_address,
                        src_address,
                        payload_encryption,
                        udp_data,
                        _marker: &PhantomData,
                    },
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                    _marker: &PhantomData,
                })
            }
        }
    }
}
/// When tunnel in agent accepted state, it can connect to destination
impl<'config, 'crypto, F> Tunnel<'config, 'crypto, AgentAcceptedState<'crypto, F>, F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync + 'crypto,
{
    /// Connect the tunnel to destination
    pub async fn connect_to_destination(
        self,
    ) -> Result<Tunnel<'config, 'crypto, DestConnectedState<'crypto, F>, F>, ProxyServerError> {
        let state = self.state;
        let tunnel_id = self.tunnel_id;
        match state {
            AgentAcceptedState::Tcp {
                agent_connection_read,
                mut agent_connection_write,
                dst_address,
                src_address,
                payload_encryption,
                user_token,
                ..
            } => {
                let dst_socket_address =
                    dst_address.to_socket_addrs()?.collect::<Vec<SocketAddr>>();
                let dst_tcp_stream = timeout(
                    Duration::from_secs(self.config.dst_tcp_connect_timeout()),
                    TcpStream::connect(dst_socket_address.as_slice()),
                )
                    .await.map_err(|_| ProxyServerError::Other(format!(
                    "Tunnel [{tunnel_id}] connect to tcp destination [{dst_address}] timeout in [{}] seconds.",
                    self.config.dst_tcp_connect_timeout()
                )))?.map_err(|e| {
                    error!("Tunnel [{tunnel_id}] connect to tcp destination [{dst_address}] fail because of error: {e:?}");
                    ProxyServerError::StdIo(e)
                })?;
                dst_tcp_stream.set_nodelay(true)?;
                dst_tcp_stream.set_linger(None)?;
                let mut dst_tcp_stream = TimeoutStream::new(TfoStream::from(dst_tcp_stream));
                dst_tcp_stream.set_read_timeout(Some(Duration::from_secs(
                    self.config.dst_tcp_read_timeout(),
                )));
                dst_tcp_stream.set_write_timeout(Some(Duration::from_secs(
                    self.config.dst_tcp_write_timeout(),
                )));
                let dst_connection = Framed::with_capacity(
                    dst_tcp_stream,
                    BytesCodec::new(),
                    self.config.dst_connection_codec_framed_buffer_size(),
                );
                let tcp_init_success_message =
                    PpaassMessageGenerator::generate_proxy_tcp_init_message(
                        user_token.clone(),
                        src_address.clone(),
                        dst_address.clone(),
                        payload_encryption.clone(),
                        ProxyTcpInitResult::Success(tunnel_id.clone()),
                    )?;
                agent_connection_write
                    .send(tcp_init_success_message)
                    .await?;
                Ok(Tunnel {
                    tunnel_id,
                    state: DestConnectedState::Tcp {
                        user_token,
                        agent_connection_read,
                        agent_connection_write,
                        payload_encryption,
                        dst_connection,
                        _marker: &PhantomData,
                    },
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                    _marker: &PhantomData,
                })
            }
            AgentAcceptedState::Udp {
                user_token,
                dst_address,
                src_address,
                payload_encryption,
                udp_data,
                agent_connection_write,
                agent_connection_read,
                ..
            } => {
                let dst_udp_socket = UdpSocket::bind(LOCAL_UDP_BIND_ADDR).await?;
                let dst_socket_addrs = dst_address.to_socket_addrs()?;
                let dst_socket_addrs = dst_socket_addrs.collect::<Vec<SocketAddr>>();
                timeout(
                    Duration::from_secs(self.config.dst_udp_connect_timeout()),
                    dst_udp_socket.connect(dst_socket_addrs.as_slice()),
                )
                    .await.map_err(|_| {
                    ProxyServerError::Other(format!("Tunnel [{tunnel_id}] connect to destination udp socket [{dst_address}] timeout in [{}] seconds.", self.config.dst_udp_connect_timeout()))
                })?.map_err(|e| {
                    error!("Tunnel [{tunnel_id}] connect to destination udp socket [{dst_address}] fail because of error: {e:?}");
                    ProxyServerError::StdIo(e)
                })?;
                Ok(Tunnel {
                    tunnel_id,
                    state: DestConnectedState::Udp {
                        user_token,
                        agent_connection_write,
                        agent_connection_read,
                        dst_address,
                        src_address,
                        payload_encryption,
                        dst_udp_socket,
                        udp_data,
                        _marker: &PhantomData,
                    },
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                    _marker: &PhantomData,
                })
            }
        }
    }
}
/// When tunnel in destination connected state, it can start relay.
impl<'config, 'crypto, F> Tunnel<'config, 'crypto, DestConnectedState<'crypto, F>, F>
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
    /// Relay the data through the tunnel between agent and destination
    pub async fn relay(self) -> Result<Tunnel<'config, 'crypto, RelayState, F>, ProxyServerError> {
        //Read the first message from agent connection
        let tunnel_id = self.tunnel_id;
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
                let tunnel_id_clone = tunnel_id.clone();
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
                        error!("Tunnel [{tunnel_id_clone}] error happen when relay tcp data from agent to destination: {e:?}");
                    }
                });
                let tunnel_id_clone = tunnel_id.clone();
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
                        error!("Tunnel [{tunnel_id_clone}] error happen when relay tcp data from destination to agent: {e:?}", );
                    }
                });
                Ok(Tunnel {
                    tunnel_id,
                    state: RelayState,
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                    _marker: &PhantomData,
                })
            }
            DestConnectedState::Udp {
                user_token,
                mut agent_connection_write,
                mut agent_connection_read,
                dst_address,
                src_address,
                payload_encryption,
                dst_udp_socket,
                udp_data,
                ..
            } => {
                dst_udp_socket.send(&udp_data).await.map_err(|e| {
                    error!("Tunnel [{tunnel_id}] fail to relay agent udp data to destination udp socket [{dst_address}] because of error: {e:?}");
                    ProxyServerError::StdIo(e)
                })?;
                let tunnel_id_clone = tunnel_id.clone();
                let dst_udp_recv_timeout = self.config.dst_udp_recv_timeout();
                let dst_udp_socket = Arc::new(dst_udp_socket);
                let dst_udp_socket_clone = dst_udp_socket.clone();
                tokio::spawn(async move {
                    loop {
                        let agent_udp_data = match StreamExt::next(&mut agent_connection_read).await
                        {
                            None => return,
                            Some(Ok(agent_udp_message)) => agent_udp_message,
                            Some(Err(e)) => {
                                error!("Tunnel [{tunnel_id_clone}] error happen when relay agent udp data to destination: {e:?}", );
                                return;
                            }
                        };
                        let PpaassAgentMessagePayload::Udp(AgentUdpPayload { data, .. }) =
                            agent_udp_data.payload
                        else {
                            error!(
                                "Tunnel [{tunnel_id_clone}] receive invalid udp data from agent",
                            );
                            return;
                        };
                        if let Err(e) = dst_udp_socket_clone.send(&data).await {
                            error!("Tunnel [{tunnel_id_clone}] error happen when send agent udp data to destination: {e:?}", );
                            return;
                        };
                    }
                });
                let tunnel_id_clone = tunnel_id.clone();
                tokio::spawn(async move {
                    // spawn a task for receive data from destination udp socket.
                    loop {
                        let mut udp_recv_buf = [0u8; MAX_UDP_PACKET_SIZE];
                        let udp_recv_buf = match timeout(
                            Duration::from_secs(dst_udp_recv_timeout),
                            dst_udp_socket.recv(&mut udp_recv_buf),
                        )
                        .await
                        {
                            Err(_) => {
                                return Err(ProxyServerError::Other(format!("Tunnel [{tunnel_id_clone}] receive data from destination udp socket [{dst_address}] timeout in [{dst_udp_recv_timeout}] seconds.")));
                            }
                            Ok(Err(e)) => {
                                error!("Tunnel [{tunnel_id_clone}] fail to receive data from destination udp socket [{dst_address}] because of error: {e:?}");
                                return Err(ProxyServerError::StdIo(e));
                            }
                            Ok(Ok(0)) => {
                                debug!("Tunnel [{tunnel_id_clone}] receive all data from destination udp socket [{dst_address}],last receive data size is zero.");
                                return Ok(());
                            }
                            Ok(Ok(size)) => &udp_recv_buf[..size],
                        };
                        let udp_data_message =
                            PpaassMessageGenerator::generate_proxy_udp_data_message(
                                user_token.clone(),
                                payload_encryption.clone(),
                                src_address.clone(),
                                dst_address.clone(),
                                Bytes::from(udp_recv_buf.to_vec()),
                            )?;
                        if let Err(e) = agent_connection_write.send(udp_data_message).await {
                            error!("Tunnel [{tunnel_id_clone}] fail to relay destination udp socket data [{dst_address}] udp data to agent because of error: {e:?}");
                            return Ok(());
                        };
                    }
                });
                Ok(Tunnel {
                    tunnel_id,
                    state: RelayState,
                    config: self.config,
                    rsa_crypto_fetcher: self.rsa_crypto_fetcher,
                    _marker: &PhantomData,
                })
            }
        }
    }
}
