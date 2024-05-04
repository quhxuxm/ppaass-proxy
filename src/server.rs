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
        let tcp_listener = match TcpListener::bind(&tcp_bind_addr).await {
            Ok(tcp_listener) => tcp_listener,
            Err(e) => {
                error!("Proxy server fail to bind tcp port for serve because of error: {e:?}");
                return Err(e.into());
            }
        };
        info!(
            "Proxy server start to serve tcp connection on address(ip v6={}): {tcp_bind_addr}.",
            self.config.get_ipv6()
        );
        loop {
            let (agent_tcp_stream, agent_socket_address) =
                match Self::accept_agent_tcp_connection(&tcp_listener).await {
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
