use crate::{
    config::ProxyConfig,
    error::ProxyServerError,
    tunnel::{InitState, Tunnel},
};
use ppaass_crypto::crypto::RsaCryptoFetcher;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_tfo::{TfoListener, TfoStream};
use tracing::{debug, error, info};
/// The ppaass proxy server.
pub struct ProxyServer<F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync + 'static,
{
    config: &'static ProxyConfig,
    rsa_crypto_fetcher: F,
}
impl<F> ProxyServer<F>
where
    F: RsaCryptoFetcher + Clone + Send + Sync + 'static,
{
    pub fn new(config: &'static ProxyConfig, rsa_crypto_fetcher: F) -> Self {
        Self {
            config,
            rsa_crypto_fetcher,
        }
    }
    /// Accept agent connection
    async fn accept_agent_tcp_connection(
        tcp_listener: &TfoListener,
    ) -> Result<(TfoStream, SocketAddr), ProxyServerError> {
        let (agent_tcp_stream, agent_socket_address) = tcp_listener.accept().await?;
        agent_tcp_stream.set_linger(None)?;
        agent_tcp_stream.set_nodelay(true)?;
        Ok((agent_tcp_stream, agent_socket_address))
    }
    /// Start the proxy server instance.
    pub async fn start(self) -> Result<(), ProxyServerError> {
        let tcp_port = self.config.tcp_port();
        let tcp_bind_addr: SocketAddr = if self.config.ipv6() {
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
            self.config.ipv6()
        );
        let tcp_listener = TfoListener::from_tokio(tcp_listener)?;
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
            let tunnel: Tunnel<InitState, F> =
                Tunnel::new(&self.config, self.rsa_crypto_fetcher.clone());
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
        tunnel: Tunnel<'static, 'static, InitState, F>,
        agent_tcp_stream: TfoStream,
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
