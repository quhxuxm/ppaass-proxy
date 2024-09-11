use self::state::SessionState;
use crate::crypto::ProxyServerPayloadEncryptionSelector;
use crate::error::ProxyServerError;
use crate::session::state::AgentAcceptedData;
use crate::{codec::PpaassAgentEdgeCodec, config::ProxyConfig};
use bytes::{Bytes, BytesMut};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use ppaass_crypto::{crypto::RsaCryptoFetcher, random_32_bytes};
use ppaass_protocol::message::payload::udp::AgentUdpPayload;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use ppaass_protocol::message::{payload::tcp::AgentTcpPayload, PpaassProxyMessage};
use ppaass_protocol::message::{PpaassAgentMessage, PpaassAgentMessagePayload};
use ppaass_protocol::{
    generator::PpaassMessageGenerator, message::payload::tcp::ProxyTcpInitResult,
};
use pretty_hex::pretty_hex;
use state::DestConnectedData;
use std::net::SocketAddr;
use std::{mem::replace, mem::take};
use std::{net::ToSocketAddrs, time::Duration};
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
/// The session between agent and destination
pub struct Session<'config, F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync + 'static,
{
    /// The id of the session
    id: String,
    /// The state of the session
    state: SessionState<F>,
    /// The configuration of the proxy
    config: &'config ProxyConfig,
    rsa_crypto_fetcher: F,
}
impl<'config, F> Session<'config, F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync,
{
    /// Create a new session
    pub fn new(config: &'config ProxyConfig, rsa_crypto_fetcher: F) -> Session<'config, F> {
        Self {
            id: Uuid::new_v4().to_string(),
            state: SessionState::Init,
            config,
            rsa_crypto_fetcher,
        }
    }

    /// Get the id of the session
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Get the state of the session
    pub fn state(&self) -> &SessionState<F> {
        &self.state
    }

    /// Accept the agent connection
    pub async fn accept_agent_connection(
        &mut self,
        agent_tcp_stream: TfoStream,
    ) -> Result<PpaassUnifiedAddress, ProxyServerError> {
        let session_id = &self.id;
        let SessionState::Init = self.state else {
            return Err(ProxyServerError::Other(format!(
                "Session [{session_id}] in invalid state: {}",
                self.state
            )));
        };
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
                    "Session [{session_id}] fail to accept agent connection because of exhausted."
                )))?.map_err(|e| {
                error!("Session [{session_id}] fail to read data from agent connection because of error: {e:?}");
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
                        "Session [{session_id}] expect to receive tcp init message but it is not: {payload_content:?}"
                    )));
                };
                debug!("Session [{session_id}] receive tcp init message[{message_id}], src address: {src_address}, dst address: {dst_address}");
                self.state = SessionState::AgentAccepted(AgentAcceptedData::Tcp {
                    user_token,
                    agent_connection_read,
                    agent_connection_write,
                    src_address,
                    dst_address: dst_address.clone(),
                    payload_encryption,
                });
                Ok(dst_address)
            }
            PpaassAgentMessagePayload::Udp(payload_content) => {
                let AgentUdpPayload {
                    src_address,
                    dst_address,
                    data: udp_data,
                } = payload_content;
                debug!("Session [{session_id}] receive udp data message[{message_id}], src address: {src_address}, dst address: {dst_address}");
                trace!(
                    "Session [{session_id}] receive udp data: {}",
                    pretty_hex(&udp_data)
                );
                // Udp session will block the thread and continue to
                // handle the agent connection in a loop
                self.state = SessionState::AgentAccepted(AgentAcceptedData::Udp {
                    user_token,
                    agent_connection_write,
                    agent_connection_read,
                    src_address,
                    dst_address: dst_address.clone(),
                    payload_encryption,
                    udp_data,
                });
                Ok(dst_address)
            }
        }
    }

    /// Connect the session to destination
    pub async fn connect_to_destination(&mut self) -> Result<(), ProxyServerError> {
        let session_id = self.id.to_owned();
        debug!("Session [{session_id}] connecting destination ...");
        let session_state = take(&mut self.state);
        let SessionState::AgentAccepted(agent_connection) = session_state else {
            return Err(ProxyServerError::Other(format!(
                "Session [{session_id}] in invalid state: {session_state}",
            )));
        };

        match agent_connection {
            AgentAcceptedData::Tcp {
                agent_connection_read,
                mut agent_connection_write,
                src_address,
                dst_address,
                payload_encryption,
                user_token,
            } => {
                let dst_socket_address =
                    dst_address.to_socket_addrs()?.collect::<Vec<SocketAddr>>();
                let dst_tcp_stream = timeout(
                    Duration::from_secs(self.config.dst_tcp_connect_timeout()),
                    TcpStream::connect(dst_socket_address.as_slice()),
                )
                    .await.map_err(|_| ProxyServerError::Other(format!(
                    "Session [{session_id}] connect to tcp destination [{dst_address}] timeout in [{}] seconds.",
                    self.config.dst_tcp_connect_timeout()
                )))?.map_err(|e| {
                    error!("Session [{session_id}] connect to tcp destination [{dst_address}] fail because of error: {e:?}");
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
                        ProxyTcpInitResult::Success(session_id.clone()),
                    )?;
                agent_connection_write
                    .send(tcp_init_success_message)
                    .await?;

                self.state = SessionState::DestConnected(DestConnectedData::Tcp {
                    user_token,
                    agent_connection_read,
                    agent_connection_write,
                    src_address,
                    payload_encryption,
                    dst_address,
                    dst_connection,
                });

                Ok(())
            }
            AgentAcceptedData::Udp {
                user_token,
                src_address,
                dst_address,
                payload_encryption,
                udp_data,
                agent_connection_write,
                agent_connection_read,
                ..
            } => {
                let dest_udp = UdpSocket::bind(LOCAL_UDP_BIND_ADDR).await?;
                let dst_socket_addrs = dst_address.to_socket_addrs()?;
                let dst_socket_addrs = dst_socket_addrs.collect::<Vec<SocketAddr>>();
                timeout(
                    Duration::from_secs(self.config.dst_udp_connect_timeout()),
                    dest_udp.connect(dst_socket_addrs.as_slice()),
                )
                    .await.map_err(|_| {
                    ProxyServerError::Other(format!("Session [{session_id}] connect to destination udp socket [{dst_address}] timeout in [{}] seconds.", self.config.dst_udp_connect_timeout()))
                })?.map_err(|e| {
                    error!("Session [{session_id}] connect to destination udp socket [{dst_address}] fail because of error: {e:?}");
                    ProxyServerError::StdIo(e)
                })?;

                self.state = SessionState::DestConnected(DestConnectedData::Udp {
                    user_token,
                    agent_connection_write,
                    _agent_connection_read: agent_connection_read,
                    src_address,
                    payload_encryption,
                    dst_address,
                    dst_udp: dest_udp,
                    udp_data,
                });
                Ok(())
            }
        }
    }

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
    /// Relay the data through the session between agent and destination
    pub async fn relay(&mut self) -> Result<(), ProxyServerError> {
        //Read the first message from agent connection
        let session_id = self.id.to_owned();
        let sesion_state = replace(&mut self.state, SessionState::Relay);
        let SessionState::DestConnected(dest_connected_data) = sesion_state else {
            return Err(ProxyServerError::Other(format!(
                "Session [{session_id}] in invalid agent state: {sesion_state}",
            )));
        };

        match dest_connected_data {
            DestConnectedData::Tcp {
                user_token,
                agent_connection_read,
                mut agent_connection_write,
                payload_encryption,
                dst_connection,
                src_address,
                dst_address,
                ..
            } => {
                let (mut dst_connection_write, dst_connection_read) = dst_connection.split();
                let session_id_clone = session_id.clone();
                let src_address_clone = src_address.clone();
                let dst_address_clone = dst_address.clone();
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
                        error!("Session [{session_id_clone}] error happen when relay tcp data from source [{src_address_clone}] to destination [{dst_address_clone}]: {e:?}");
                    }
                });

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
                        error!("Session [{session_id}] error happen when relay tcp data from destination [{dst_address}] to source [{src_address}]: {e:?}", );
                    }
                });
                Ok(())
            }
            DestConnectedData::Udp {
                user_token,
                mut agent_connection_write,
                src_address,
                payload_encryption,
                dst_udp,
                dst_address,
                udp_data,
                ..
            } => {
                dst_udp.send(&udp_data).await.map_err(|e| {
                    error!("Session [{session_id}] fail to relay agent udp data from source [{src_address}] to destination [{dst_address}] because of error: {e:?}");
                    ProxyServerError::StdIo(e)
                })?;
                let dst_udp_recv_timeout = self.config.dst_udp_recv_timeout();
                let session_id = session_id.clone();
                tokio::spawn(async move {
                    // spawn a task for receive data from destination udp socket.
                    let mut udp_recv_buf = [0u8; MAX_UDP_PACKET_SIZE];
                    let udp_recv_buf = match timeout(
                        Duration::from_secs(dst_udp_recv_timeout),
                        dst_udp.recv(&mut udp_recv_buf),
                    )
                    .await
                    {
                        Err(_) => {
                            error!("Session [{session_id}] receive udp data from destination [{dst_address}] to source [{src_address}], timeout in [{dst_udp_recv_timeout}] seconds.");
                            return;
                        }
                        Ok(Err(e)) => {
                            error!("Session [{session_id}] fail to receive udp data from destination [{dst_address}] to source [{src_address}] because of error: {e:?}");
                            return;
                        }
                        Ok(Ok(0)) => {
                            debug!("Session [{session_id}] receive all udp data from destination [{dst_address}] to source [{src_address}], last receive data size is zero.");
                            return;
                        }
                        Ok(Ok(size)) => &udp_recv_buf[..size],
                    };
                    let udp_data_message =
                        match PpaassMessageGenerator::generate_proxy_udp_data_message(
                            user_token.clone(),
                            payload_encryption.clone(),
                            src_address.clone(),
                            dst_address.clone(),
                            Bytes::from(udp_recv_buf.to_vec()),
                        ) {
                            Ok(udp_data_message) => udp_data_message,
                            Err(e) => {
                                error!("Session [{session_id}] fail to generate udp data from destination [{dst_address}] to to source [{src_address}] because of error: {e:?}");
                                return;
                            }
                        };
                    if let Err(e) = agent_connection_write.send(udp_data_message).await {
                        error!("Session [{session_id}] fail to relay destination udp data from destination [{dst_address}] to source [{src_address}] because of error: {e:?}");
                    };
                });
                Ok(())
            }
        }
    }
}
