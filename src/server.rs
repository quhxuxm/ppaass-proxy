use crate::{
    config::SERVER_CONFIG, error::ProxyError, transport::TcpTransport, RSA_CRYPTO_FETCHER,
};

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info};
use ppaass_protocol::message::agent::{
    AgentMessage, AgentMessagePayload, CloseTunnelCommand, InitTunnelCommand, RelayData,
};

use crate::connection::{AgentConnection, AgentConnectionRead, AgentConnectionWrite};
use ppaass_protocol::message::proxy::ProxyMessage;
use ppaass_protocol::values::tunnel::TunnelType;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
};
use uuid::Uuid;

pub(crate) struct AgentInboundMessage {
    /// The agent tcp connection id
    pub agent_connection_id: String,
    /// The payload of the agent input message
    pub agent_message: AgentMessage,
}

/// The ppaass proxy server.
pub(crate) struct Server {
    /// The container of every agent connection, the key will be the
    /// agent connection id, the value is the output sender of the connection,
    /// each proxy server will maintain number of keep alived agent connections，
    /// each tunnel will reuse these agent connections.
    agent_connection_output_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<ProxyMessage>>>>,
    /// The tunnels to transfer data from agent to destination, the key should be the
    /// tunnel id, the value is the output sender for the destination.
    tcp_tunnels: Arc<Mutex<HashMap<String, UnboundedSender<Bytes>>>>,
}

impl Server {
    pub(crate) fn new() -> Self {
        Self {
            agent_connection_output_tx_repo: Default::default(),
            tcp_tunnels: Default::default(),
        }
    }
    /// Accept agent connection
    async fn accept_agent_tcp_stream(
        tcp_listener: &TcpListener,
    ) -> Result<(TcpStream, SocketAddr), ProxyError> {
        let (agent_tcp_stream, agent_socket_address) = tcp_listener.accept().await?;
        agent_tcp_stream.set_linger(None)?;
        agent_tcp_stream.set_nodelay(true)?;
        Ok((agent_tcp_stream, agent_socket_address))
    }

    /// Start the proxy server instance.
    pub(crate) async fn start(&mut self) -> Result<(), ProxyError> {
        let port = SERVER_CONFIG.get_port();
        let bind_addr = if SERVER_CONFIG.get_ipv6() {
            format!("[::]:{port}")
        } else {
            format!("0.0.0.0:{port}")
        };
        info!(
            "Proxy server start to serve request on address(ip v6={}): {bind_addr}.",
            SERVER_CONFIG.get_ipv6()
        );

        let tcp_listener = TcpListener::bind(&bind_addr).await?;
        let (agent_tcp_inbound_tx, agent_tcp_inbound_rx) =
            unbounded_channel::<AgentInboundMessage>();
        let (agent_udp_inbound_tx, agent_udp_inbound_rx) =
            unbounded_channel::<AgentInboundMessage>();

        Self::handle_agent_tcp_inbound(
            agent_tcp_inbound_rx,
            self.agent_connection_output_tx_repo.clone(),
            self.tcp_tunnels.clone(),
        );
        Self::handle_udp_tunnel_inbound(
            agent_udp_inbound_rx,
            self.agent_connection_output_tx_repo.clone(),
        );

        // Start the loop for accept agent connection
        loop {
            let (agent_tcp_stream, agent_address) =
                match Self::accept_agent_tcp_stream(&tcp_listener).await {
                    Ok(accept_result) => accept_result,
                    Err(e) => {
                        error!(
                            "Proxy server fail to accept agent connection because of error: {e:?}"
                        );
                        continue;
                    }
                };
            let agent_connection = AgentConnection::new(
                agent_tcp_stream,
                RSA_CRYPTO_FETCHER
                    .get()
                    .expect("Fail to get rsa crypto fetcher because of unknown reason.")
                    .clone(),
                SERVER_CONFIG.get_compress(),
                65536,
            );
            let agent_connection_id = Uuid::new_v4().to_string();
            let (agent_connection_write, agent_connection_read) = agent_connection.split();
            let (agent_connection_output_tx, agent_connection_output_rx) =
                unbounded_channel::<ProxyMessage>();
            self.agent_connection_output_tx_repo.lock().await.insert(
                agent_connection_id.clone(),
                agent_connection_output_tx.clone(),
            );
            debug!("Proxy server success accept new agent connection [{agent_connection_id}] on address: {agent_address}");
            // Start the task to handle the raw agent tcp connection output
            Self::handle_agent_connection_output(
                agent_connection_id.clone(),
                agent_connection_output_rx,
                agent_connection_write,
            );

            // Start the task to handle the raw agent tcp connection input
            Self::handle_agent_connection_input(
                agent_connection_id.clone(),
                agent_tcp_inbound_tx.clone(),
                agent_udp_inbound_tx.clone(),
                agent_connection_read,
            );

            let mut agent_connection_output_tx_repo =
                self.agent_connection_output_tx_repo.lock().await;
            agent_connection_output_tx_repo
                .insert(agent_connection_id.clone(), agent_connection_output_tx);
        }
    }

    fn handle_agent_tcp_inbound(
        mut agent_tcp_inbound_rx: UnboundedReceiver<AgentInboundMessage>,
        agent_connection_output_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<ProxyMessage>>>>,
        tcp_tunnels: Arc<Mutex<HashMap<String, UnboundedSender<Bytes>>>>,
    ) {
        tokio::spawn(async move {
            // Forward a wrapper message to a agent connection.
            while let Some(agent_inbound_message) = agent_tcp_inbound_rx.recv().await {
                let AgentInboundMessage {
                    agent_connection_id,
                    agent_message,
                } = agent_inbound_message;
                let AgentMessage {
                    message_id,
                    secure_info,
                    tunnel,
                    payload,
                } = agent_message;

                match payload {
                    AgentMessagePayload::InitTunnelCommand(InitTunnelCommand {
                        src_address,
                        dst_address,
                    }) => {
                        let tunnel = tunnel.clone();
                        let agent_connection_output_tx_repo =
                            agent_connection_output_tx_repo.clone();
                        let tcp_tunnels = tcp_tunnels.clone();
                        tokio::spawn(async move {
                            let agent_connection_output_tx = {
                                let agent_connection_output_tx_repo =
                                    agent_connection_output_tx_repo.lock().await;
                                let Some(agent_connection_output_tx) =
                                    agent_connection_output_tx_repo.get(&agent_connection_id)
                                else {
                                    error!("Can not find agent connection output sender by id: {agent_connection_id}");
                                    return Err(ProxyError::Other(format!("Can not find agent connection output sender by id: {agent_connection_id}")));
                                };
                                agent_connection_output_tx.clone()
                            };
                            let (transport_relay_tx, transport_relay_rx) = unbounded_channel();
                            let proxy_edge_id = Uuid::new_v4().to_string();
                            let mut transport = TcpTransport::new(
                                tunnel.agent_edge_id,
                                proxy_edge_id.clone(),
                                src_address,
                                dst_address,
                                secure_info.user_token,
                                agent_connection_id,
                                transport_relay_rx,
                                agent_connection_output_tx,
                            );

                            transport.connect().await?;
                            tcp_tunnels
                                .lock()
                                .await
                                .insert(proxy_edge_id.clone(), transport_relay_tx);
                            if let Err(e) = transport.exec().await {
                                error!("Fail to execute transport because of error: {e:?}");
                                tcp_tunnels.lock().await.remove(&proxy_edge_id);
                                return Err(e);
                            };
                            tcp_tunnels.lock().await.remove(&proxy_edge_id);
                            Ok::<(), ProxyError>(())
                        });
                    }
                    AgentMessagePayload::RelayData(RelayData {
                        src_address,
                        dst_address,
                        data,
                    }) => {
                        let proxy_edge_id = match tunnel.proxy_edge_id {
                            None => {
                                error!("Fail to relay tcp data because of no proxy edge assigned");
                                return;
                            }
                            Some(proxy_edge_id) => proxy_edge_id,
                        };
                        let mut tcp_tunnels = tcp_tunnels.lock().await;
                        if let Some(transport_relay_tx) = tcp_tunnels.get(&proxy_edge_id) {
                            if let Err(e) = transport_relay_tx.send(data) {
                                error!("Transport [{proxy_edge_id}] fail to send agent tcp data for relay because of error: {e:?}");
                                tcp_tunnels.remove(&proxy_edge_id);
                            };
                        }
                    }
                    AgentMessagePayload::CloseTunnelCommand(CloseTunnelCommand {
                        src_address,
                        dst_address,
                    }) => {
                        let proxy_edge_id = match tunnel.proxy_edge_id {
                            None => {
                                error!("Fail to close tunnel because of no proxy edge assigned");
                                return;
                            }
                            Some(proxy_edge_id) => proxy_edge_id,
                        };
                        debug!("Transport [{proxy_edge_id}] receive tcp close request from agent, close it.");
                        let mut transports = tcp_tunnels.lock().await;
                        transports.remove(&proxy_edge_id);
                    }
                }
            }
        });
    }

    fn handle_udp_tunnel_inbound(
        mut _agent_udp_inbound_rx: UnboundedReceiver<AgentInboundMessage>,
        _agent_connection_output_tx_repo: Arc<
            Mutex<HashMap<String, UnboundedSender<ProxyMessage>>>,
        >,
    ) {
        tokio::spawn(async move {
            // Forward a wrapper message to a agent connection.
            todo!()
        });
    }

    fn handle_agent_connection_output(
        agent_connection_id: String,
        mut agent_connection_output_rx: UnboundedReceiver<ProxyMessage>,
        mut agent_connection_write: AgentConnectionWrite,
    ) {
        tokio::spawn(async move {
            // Spawn a task write output to agent
            while let Some(proxy_message) = agent_connection_output_rx.recv().await {
                if let Err(e) = agent_connection_write.send(proxy_message).await {
                    error!("Fail to write data to agent connection [{agent_connection_id}] because of error: {e:?}");
                    return;
                };
            }
        });
    }

    fn handle_agent_connection_input(
        agent_connection_id: String,
        agent_tcp_inbound_tx: UnboundedSender<AgentInboundMessage>,
        agent_udp_inbound_tx: UnboundedSender<AgentInboundMessage>,
        mut agent_connection_read: AgentConnectionRead,
    ) {
        tokio::spawn(async move {
            // Spawn a task read input from agent
            while let Some(agent_message) = agent_connection_read.next().await {
                let agent_message = match agent_message {
                    Ok(agent_message) => agent_message,
                    Err(e) => {
                        error!("Fail to read data from agent connection [{agent_connection_id}] because of error: {e:?}");
                        return;
                    }
                };
                let tunnel = &agent_message.tunnel;
                match tunnel.tunnel_type {
                    TunnelType::Tcp => {
                        if let Err(e) = agent_tcp_inbound_tx.send(AgentInboundMessage {
                            agent_message,
                            agent_connection_id: agent_connection_id.clone(),
                        }) {
                            error!("Fail to forward input for agent connection [{agent_connection_id}] because of error: {e:?}");
                        };
                    }
                    TunnelType::Udp => {
                        if let Err(e) = agent_udp_inbound_tx.send(AgentInboundMessage {
                            agent_message,
                            agent_connection_id: agent_connection_id.clone(),
                        }) {
                            error!("Fail to forward input for agent connection [{agent_connection_id}] because of error: {e:?}");
                        };
                    }
                }
            }
        });
    }
}
