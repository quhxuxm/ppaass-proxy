use crate::{
    config::ProxyConfig,
    error::ProxyServerError,
    transport::{InitState, Transport},
};

use std::net::SocketAddr;

use ppaass_crypto::crypto::RsaCryptoFetcher;
use tracing::{debug, error, info};

use tokio::net::{TcpListener, TcpStream};

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
            let transport: Transport<InitState, F> =
                Transport::new(self.config, self.rsa_crypto_fetcher);
            debug!("Proxy server success accept agent tcp connection on address [{agent_socket_address}] and assign transport for it: {}", transport.get_id());

            tokio::spawn(async move {
                let transport_id = transport.get_id().to_owned();
                if let Err(e) =
                    Self::process_agent_tcp_connection(transport, agent_tcp_stream).await
                {
                    error!("Transport [{transport_id}] fail to process agent tcp connection because of error: {e:?}")
                };
            });
        }
    }

    /// Process the agent tcp connection with transport
    async fn process_agent_tcp_connection(
        transport: Transport<'config, 'crypto, InitState, F>,
        agent_tcp_stream: TcpStream,
    ) -> Result<(), ProxyServerError> {
        let transport = transport.accept_agent_connection(agent_tcp_stream).await?;
        debug!(
            "Transport [{}] success accept the agent connection, state={}.",
            transport.get_id(),
            transport.get_state()
        );
        let transport = transport.connect_to_destinition().await?;
        debug!(
            "Transport [{}] success connect to destination, state={}.",
            transport.get_id(),
            transport.get_state()
        );
        let transport = transport.relay().await?;
        debug!(
            "Transport [{}] success start relay, state={}.",
            transport.get_id(),
            transport.get_state()
        );
        Ok(())
    }
}
