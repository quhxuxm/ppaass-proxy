use crate::{config::ProxyConfig, error::ProxyServerError, session::Session};
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
        let tcp_listener = TcpListener::bind(&tcp_bind_addr).await?;
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
            let session = Session::new(self.config, self.rsa_crypto_fetcher.clone());
            debug!("Proxy server success accept agent tcp connection on address [{agent_socket_address}] and assign session for it: {}", session.id());
            tokio::spawn(async move {
                let session_id = session.id().to_owned();
                if let Err(e) = Self::process_agent_tcp_connection(session, agent_tcp_stream).await
                {
                    error!("Session [{session_id}] fail to process agent tcp connection because of error: {e:?}")
                };
            });
        }
    }
    /// Process the agent tcp connection with session
    async fn process_agent_tcp_connection(
        mut session: Session<'static, F>,
        agent_tcp_stream: TfoStream,
    ) -> Result<(), ProxyServerError> {
        let session_id = session.id().to_owned();
        let dest_address = session.accept_agent_connection(agent_tcp_stream).await?;
        debug!(
            "Session [{session_id}] success accept the agent connection going to connect destination [{dest_address}], agent state={}.",
            session.state()
        );
        session.connect_to_destination().await?;
        debug!(
            "Session [{session_id}] success connect to destination [{dest_address}], state={}.",
            session.state()
        );
        session.relay().await?;
        debug!(
            "Session [{session_id}] success start relay, state={}.",
            session.state()
        );
        Ok(())
    }
}
