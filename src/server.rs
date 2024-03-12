use crate::{
    config::PROXY_CONFIG,
    error::ProxyServerError,
    trace::{self},
    transport::{InitState, Transport},
};

use std::net::SocketAddr;

use tracing::{debug, error, info};

use tokio::net::{TcpListener, TcpStream};

const TRANSPORT_MONITOR_FILE_PREFIX: &str = "transport";

/// The ppaass proxy server.
#[derive(Default)]
pub(crate) struct ProxyServer {}

impl ProxyServer {
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
        let port = PROXY_CONFIG.get_port();
        let bind_addr = if PROXY_CONFIG.get_ipv6() {
            format!("[::]:{port}")
        } else {
            format!("0.0.0.0:{port}")
        };
        info!(
            "Proxy server start to serve request on address(ip v6={}): {bind_addr}.",
            PROXY_CONFIG.get_ipv6()
        );
        let (_transport_trace_subscriber, _transport_trace_guard) =
            trace::init_transport_tracing_subscriber(
                TRANSPORT_MONITOR_FILE_PREFIX,
                PROXY_CONFIG.get_transport_max_log_level(),
            )?;

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
            let transport: Transport<InitState> = Transport::new();
            debug!("Proxy server success accept agent tcp connection on address [{agent_socket_address}] and assign transport for it: {}", transport.get_id());

            tokio::spawn(async move {
                if let Err(e) =
                    Self::process_agent_tcp_connection(transport, agent_tcp_stream).await
                {
                    error!("Fail to process agent tcp connection because of error: {e:?}")
                };
            });
        }
    }

    /// Process the agent tcp connection with transport
    async fn process_agent_tcp_connection(
        transport: Transport<InitState>,
        agent_tcp_stream: TcpStream,
    ) -> Result<(), ProxyServerError> {
        let transport = transport.accept_agent_connection(agent_tcp_stream).await?;
        debug!(
            "Transport [{}] success accept the agent connection.",
            transport.get_id()
        );
        let transport = transport.connect_to_destinition().await?;
        debug!(
            "Transport [{}] success connect to destination.",
            transport.get_id()
        );
        let transport = transport.relay().await?;
        debug!("Transport [{}] success start relay.", transport.get_id());
        Ok(())
    }
}
