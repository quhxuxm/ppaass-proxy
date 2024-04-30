use crate::{
    config::ProxyConfig,
    error::ProxyServerError,
    tunnel::{InitState, Tunnel},
};
use ppaass_crypto::crypto::RsaCryptoFetcher;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};
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
    /// Accept agent connection
    async fn accept_agent_connection(
        tcp_listener: &TcpListener,
    ) -> Result<(TcpStream, SocketAddr), ProxyServerError> {
        let (agent_tcp_stream, agent_socket_address) = tcp_listener.accept().await?;
        agent_tcp_stream.set_linger(None)?;
        agent_tcp_stream.set_nodelay(true)?;
        Ok((agent_tcp_stream, agent_socket_address))
    }
    /// Start the proxy server instance.
    pub(crate) async fn start(self) -> Result<(), ProxyServerError> {
        let port = self.config.get_port();
        let bind_addr = if self.config.get_ipv6() {
            format!("[::]:{port}")
        } else {
            format!("0.0.0.0:{port}")
        };
        info!(
            "Proxy server start to serve request on address(ip v6={}): {bind_addr}.",
            self.config.get_ipv6()
        );
        let tcp_listener = TcpListener::bind(&bind_addr).await?;
        loop {
            let (agent_tcp_stream, agent_socket_address) =
                match Self::accept_agent_connection(&tcp_listener).await {
                    Ok(accept_result) => accept_result,
                    Err(e) => {
                        error!(
                            "Proxy server fail to accept agent connection because of error: {e:?}"
                        );
                        continue;
                    }
                };
            let tunnel: Tunnel<InitState, F> = Tunnel::new(self.config, self.rsa_crypto_fetcher);
            debug!("Proxy server success accept agent tcp connection on address [{agent_socket_address}] and assign tunnel for it: {}", tunnel.get_id());
            tokio::spawn(async move {
                let tunnel_id = tunnel.get_id().to_owned();
                if let Err(e) = Self::process_agent_tcp_connection(tunnel, agent_tcp_stream).await {
                    error!("Tunnel [{tunnel_id}] fail to process agent tcp connection because of error: {e:?}")
                };
            });
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
