use crate::{config::PROXY_CONFIG, error::ProxyServerError, trace, transport::Transport};

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tracing::{debug, error, info};

use crate::trace::TransportTraceType;
use tokio::net::{TcpListener, TcpStream};

const TRANSPORT_MONITOR_FILE_PREFIX: &str = "transport";

/// The ppaass proxy server.
#[derive(Default)]
pub(crate) struct ProxyServer {
    transport_number: Arc<AtomicU64>,
}

impl ProxyServer {
    pub(crate) fn new() -> Self {
        Self {
            transport_number: Arc::new(AtomicU64::new(0)),
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
        let (transport_trace_subscriber, _transport_trace_guard) =
            trace::init_transport_tracing_subscriber(
                TRANSPORT_MONITOR_FILE_PREFIX,
                PROXY_CONFIG.get_transport_max_log_level(),
            )?;
        let transport_trace_subscriber = Arc::new(transport_trace_subscriber);
        let tcp_listener = TcpListener::bind(&bind_addr).await?;
        loop {
            let transport_number = self.transport_number.clone();
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
            debug!(
                "Proxy server success accept agent connection on address: {}",
                agent_socket_address
            );
            let transport = Transport::new(
                agent_tcp_stream,
                agent_socket_address.into(),
                transport_number.clone(),
                transport_trace_subscriber.clone(),
            );
            transport_number.fetch_add(1, Ordering::Release);
            trace::trace_transport(
                transport_trace_subscriber.clone(),
                TransportTraceType::Create,
                &transport.transport_id,
                transport_number.clone(),
            );
            let transport_trace_subscriber = transport_trace_subscriber.clone();
            tokio::spawn(async move {
                let transport_id = transport.transport_id.clone();
                if let Err(e) = transport.exec().await {
                    error!("Transport [{transport_id}] execute fail because of error: {e:?}");
                    trace::trace_transport(
                        transport_trace_subscriber,
                        TransportTraceType::DropUnknown,
                        &transport_id,
                        transport_number,
                    );
                    return;
                };
                debug!(
                    "Transport [{transport_id}] spawn task success for agent connection [{agent_socket_address}].",
                );
            });
        }
    }
}
