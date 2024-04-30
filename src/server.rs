use crate::crypto::ProxyServerPayloadEncryptionSelector;

use crate::{
    config::ProxyConfig,
    error::ProxyServerError,
    tunnel::{InitState, Tunnel},
};
use bytes::{BufMut, BytesMut};

use ppaass_codec::codec::agent::PpaassAgentMessageDecoder;
use ppaass_codec::codec::proxy::PpaassProxyMessageEncoder;

use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_crypto::random_32_bytes;

use ppaass_protocol::generator::PpaassMessageGenerator;
use ppaass_protocol::message::payload::udp::AgentUdpPayload;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use ppaass_protocol::message::{PpaassAgentMessage, PpaassAgentMessagePayload};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, error, info};

const DESTINATION_UDP_SOCKET_ADDR: &str = "0.0.0.0:0";
/// The ppaass proxy server.
pub(crate) struct ProxyServer<'config, 'crypto, F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync,
{
    config: &'config ProxyConfig,
    rsa_crypto_fetcher: &'crypto F,
}
impl<'config, 'crypto, F> ProxyServer<'config, 'crypto, F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync,
    'config: 'static,
    'crypto: 'static,
{
    pub(crate) fn new(config: &'config ProxyConfig, rsa_crypto_fetcher: &'crypto F) -> Self {
        Self {
            config,
            rsa_crypto_fetcher,
        }
    }
    fn start_agent_udp_process(&self, bind_addr: SocketAddr) {
        let config = self.config;
        let rsa_crypto_fetcher = self.rsa_crypto_fetcher;
        tokio::spawn(async move {
            let proxy_server_endpoint = match UdpSocket::bind(bind_addr).await {
                Ok(proxy_server_endpoint) => proxy_server_endpoint,
                Err(e) => {
                    error!("Proxy server fail to bind udp socket because of error: {e:?}");
                    return;
                }
            };
            info!(
                "Proxy server start to serve udp packets on address(ip v6={}): {bind_addr}.",
                config.get_ipv6()
            );
            let proxy_server_endpoint = Arc::new(proxy_server_endpoint);
            loop {
                let mut agent_udp_recv_buf = BytesMut::new();
                let agent_udp_recv_buf = match proxy_server_endpoint
                    .recv(&mut agent_udp_recv_buf)
                    .await
                {
                    Ok(size) => &agent_udp_recv_buf[..size],
                    Err(e) => {
                        error!("Proxy server fail to receive udp packet from agent because of error: {e:?}");
                        continue;
                    }
                };
                let proxy_server_endpoint = proxy_server_endpoint.clone();
                let mut agent_udp_recv_buf = BytesMut::from(agent_udp_recv_buf);
                tokio::spawn(async move {
                    let mut agent_message_decoder =
                        PpaassAgentMessageDecoder::new(rsa_crypto_fetcher);
                    let mut proxy_message_encoder =
                        PpaassProxyMessageEncoder::new(config.get_compress(), rsa_crypto_fetcher);
                    let PpaassAgentMessage {
                        user_token,
                        payload: agent_message_payload,
                        ..
                    } = match agent_message_decoder.decode(&mut agent_udp_recv_buf) {
                        Ok(None) => {
                            error!("Proxy server fail to decode agent udp message because of nothing from agent udp packet.");
                            return;
                        }
                        Ok(Some(agent_message)) => agent_message,
                        Err(e) => {
                            error!(
                            "Proxy server fail to decode agent udp message because of error: {e:?}"
                        );
                            return;
                        }
                    };
                    let AgentUdpPayload {
                        src_address,
                        dst_address,
                        data,
                        ..
                    } = match agent_message_payload {
                        PpaassAgentMessagePayload::Udp(udp_payload) => udp_payload,
                        PpaassAgentMessagePayload::Tcp(_) => {
                            error!(
                            "Proxy server fail to decode agent udp message because of it is a TCP payload."
                        );
                            return;
                        }
                    };
                    let dst_socket_addrs: Vec<SocketAddr> = match dst_address.clone().try_into() {
                        Ok(dst_socket_addrs) => dst_socket_addrs,
                        Err(e) => {
                            error!(
                            "Proxy server fail to decode agent udp message because of fail to parse destination address because of error: {e:?}."
                        );
                            return;
                        }
                    };
                    let destination_udp_socket = match UdpSocket::bind(DESTINATION_UDP_SOCKET_ADDR)
                        .await
                    {
                        Ok(destination_udp_socket) => destination_udp_socket,
                        Err(e) => {
                            error!(
                            "Proxy server fail create destination udp socket because of error: {e:?}."
                        );
                            return;
                        }
                    };
                    if let Err(e) = destination_udp_socket
                        .connect(dst_socket_addrs.as_slice())
                        .await
                    {
                        error!(
                            "Proxy server fail to forward agent udp message to destination because of error: {e:?}."
                        );
                        return;
                    };
                    if let Err(e) = destination_udp_socket.send(&data).await {
                        error!(
                            "Proxy server fail to forward agent udp message to destination because of error: {e:?}."
                        );
                        return;
                    };
                    let mut destination_udp_recv_buf = BytesMut::new();
                    let destination_udp_recv_buf = match timeout(
                        Duration::from_secs(config.get_dst_udp_recv_timeout()),
                        destination_udp_socket.recv(&mut destination_udp_recv_buf),
                    )
                    .await
                    {
                        Err(_) => {
                            error!("Proxy server fail to receive destination udp message because of timeout.");
                            return;
                        }
                        Ok(Ok(size)) => &destination_udp_recv_buf[..size],
                        Ok(Err(e)) => {
                            error!("Proxy server fail to receive destination udp message because of error: {e:?}.");
                            return;
                        }
                    };
                    let destination_udp_recv_buf = BytesMut::from(destination_udp_recv_buf);

                    let proxy_server_payload_encryption =
                        ProxyServerPayloadEncryptionSelector::select(
                            &user_token,
                            Some(random_32_bytes()),
                        );
                    let proxy_udp_message =
                        match PpaassMessageGenerator::generate_proxy_udp_data_message(
                            user_token,
                            proxy_server_payload_encryption,
                            src_address,
                            dst_address,
                            destination_udp_recv_buf.freeze(),
                        ) {
                            Ok(proxy_udp_message) => proxy_udp_message,
                            Err(e) => {
                                error!(
                            "Proxy server fail to receive destination udp message because of error: {e:?}."
                        );
                                return;
                            }
                        };
                    let mut proxy_udp_packet = BytesMut::new();
                    if let Err(e) =
                        proxy_message_encoder.encode(proxy_udp_message, &mut proxy_udp_packet)
                    {
                        error!(
                            "Proxy server fail to encode udp packet to ppaass message because of error: {e:?}."
                        );
                        return;
                    };

                    let proxy_udp_packet = &proxy_udp_packet[..proxy_udp_packet.len()];
                    if let Err(e) = proxy_server_endpoint.send(proxy_udp_packet).await {
                        error!(
                            "Proxy server fail to send proxy udp packet to agent because of error: {e:?}."
                        );
                    };
                });
            }
        });
    }
    fn start_agent_tcp_process(&self, bind_addr: SocketAddr) {
        let config = self.config;
        let rsa_crypto_fetcher = self.rsa_crypto_fetcher;
        tokio::spawn(async move {
            let tcp_listener = match TcpListener::bind(&bind_addr).await {
                Ok(tcp_listener) => tcp_listener,
                Err(e) => {
                    error!("Proxy server fail to accept agent connection because of error: {e:?}");
                    return;
                }
            };
            info!(
                "Proxy server start to serve tcp connection on address(ip v6={}): {bind_addr}.",
                config.get_ipv6()
            );
            loop {
                let (agent_tcp_stream, agent_socket_address) =
                    match Self::accept_agent_tcp_connection(&tcp_listener).await {
                        Ok(accept_result) => accept_result,
                        Err(e) => {
                            error!("Proxy server fail to accept agent connection because of error: {e:?}");
                            continue;
                        }
                    };
                let tunnel: Tunnel<InitState, F> = Tunnel::new(config, rsa_crypto_fetcher);
                debug!("Proxy server success accept agent tcp connection on address [{agent_socket_address}] and assign tunnel for it: {}", tunnel.get_id());
                tokio::spawn(async move {
                    let tunnel_id = tunnel.get_id().to_owned();
                    if let Err(e) =
                        Self::process_agent_tcp_connection(tunnel, agent_tcp_stream).await
                    {
                        error!("Tunnel [{tunnel_id}] fail to process agent tcp connection because of error: {e:?}")
                    };
                });
            }
        });
    }
    /// Accept agent connection
    async fn accept_agent_tcp_connection(
        tcp_listener: &TcpListener,
    ) -> Result<(TcpStream, SocketAddr), ProxyServerError> {
        let (agent_tcp_stream, agent_socket_address) = tcp_listener.accept().await?;
        agent_tcp_stream.set_linger(None)?;
        agent_tcp_stream.set_nodelay(true)?;
        Ok((agent_tcp_stream, agent_socket_address))
    }
    /// Start the proxy server instance.
    pub(crate) async fn start(self) -> Result<(), ProxyServerError> {
        let tcp_port = self.config.get_tcp_port();
        let tcp_bind_addr: SocketAddr = if self.config.get_ipv6() {
            format!("[::]:{tcp_port}").parse()?
        } else {
            format!("0.0.0.0:{tcp_port}").parse()?
        };
        let udp_port = self.config.get_udp_port();
        let udp_bind_addr: SocketAddr = if self.config.get_ipv6() {
            format!("[::]:{udp_port}").parse()?
        } else {
            format!("0.0.0.0:{udp_port}").parse()?
        };
        self.start_agent_tcp_process(tcp_bind_addr);
        self.start_agent_udp_process(udp_bind_addr);
        loop {
            sleep(Duration::from_secs(60)).await;
        }
    }
    /// Process the agent tcp connection with tunnel
    async fn process_agent_tcp_connection(
        tunnel: Tunnel<'config, 'crypto, InitState, F>,
        agent_tcp_stream: TcpStream,
    ) -> Result<(), ProxyServerError> {
        let tunnel = tunnel.accept_agent_connection(agent_tcp_stream).await?;
        debug!(
            "Tunnel [{}] success accept the agent connection, state={}.",
            tunnel.get_id(),
            tunnel.get_state()
        );
        let tunnel = tunnel.connect_to_destination().await?;
        debug!(
            "Tunnel [{}] success connect to destination, state={}.",
            tunnel.get_id(),
            tunnel.get_state()
        );
        let tunnel = tunnel.relay().await?;
        debug!(
            "Tunnel [{}] success start relay, state={}.",
            tunnel.get_id(),
            tunnel.get_state()
        );
        Ok(())
    }
}
