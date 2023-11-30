use crate::{
    config::SERVER_CONFIG,
    error::ProxyError,
    transport::TcpTransport,
    types::{
        AgentConnectionRead, AgentConnectionWrite, AgentInputTcpMessage, AgentInputUdpMessage,
    },
    RSA_CRYPTO_FETCHER,
};

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info};

use ppaass_io::Connection as AgentConnection;
use ppaass_protocol::error::ProtocolError;
use ppaass_protocol::message::{
    AgentTcpPayload, PayloadType, UnwrappedAgentTcpMessage, WrapperMessage,
};
use ppaass_protocol::unwrap_agent_tcp_message;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
};
use uuid::Uuid;

/// The ppaass proxy server.
pub(crate) struct Server {
    /// The container of every agent connection, the key will be the
    /// agent connection id, the value is the output sender of the connection,
    /// each proxy server will maintain number of keep alived agent connections，
    /// each tunnel will reuse these agent connections.
    agent_connection_output_senders: Arc<Mutex<HashMap<String, UnboundedSender<WrapperMessage>>>>,
    /// The tunnels to transfer data from agent to destination, the key should be the
    /// tunnel id, the value is the output sender for the destination.
    tcp_tunnels: Arc<Mutex<HashMap<String, UnboundedSender<Bytes>>>>,
}

impl Server {
    pub(crate) fn new() -> Self {
        Self {
            agent_connection_output_senders: Default::default(),
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
        let (tcp_tunnel_inbound_tx, tcp_tunnel_inbound_rx) = unbounded_channel::<WrapperMessage>();
        let (udp_tunnel_inbound_tx, udp_tunnel_inbound_rx) = unbounded_channel::<WrapperMessage>();

        Self::handle_tcp_tunnel_inbound(
            tcp_tunnel_inbound_rx,
            self.agent_connection_output_senders.clone(),
            self.tcp_tunnels.clone(),
        );
        Self::handle_udp_tunnel_inbound(
            udp_tunnel_inbound_rx,
            self.agent_connection_output_senders.clone(),
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
                unbounded_channel::<WrapperMessage>();

            self.agent_connection_output_senders.lock().await.insert(
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
            Self::handle_tunnel_inbound(
                agent_connection_id.clone(),
                tcp_tunnel_inbound_tx.clone(),
                udp_tunnel_inbound_tx.clone(),
                agent_connection_read,
            );

            let mut agent_connection_output_senders =
                self.agent_connection_output_senders.lock().await;
            agent_connection_output_senders
                .insert(agent_connection_id.clone(), agent_connection_output_tx);
        }
    }

    fn handle_tcp_tunnel_inbound(
        mut tcp_tunnel_inbound_rx: UnboundedReceiver<WrapperMessage>,
        agent_connection_output_senders: Arc<
            Mutex<HashMap<String, UnboundedSender<WrapperMessage>>>,
        >,
        tcp_tunnels: Arc<Mutex<HashMap<String, UnboundedSender<Bytes>>>>,
    ) {
        tokio::spawn(async move {
            // Forward a wrapper message to a agent connection.
            while let Some(agent_message) = tcp_tunnel_inbound_rx.recv().await {
                let WrapperMessage {
                    message_id,
                    secure_info,
                    payload,
                } = agent_message;
                match payload {
                    AgentTcpPayload::InitRequest {
                        src_address,
                        dst_address,
                    } => {
                        let tcp_tunnels = tcp_tunnels.clone();
                        let agent_connection_output_senders =
                            agent_connection_output_senders.clone();

                        tokio::spawn(async move {
                            let agent_connection_output_sender = {
                                let agent_connection_output_senders =
                                    agent_connection_output_senders.lock().await;
                                let Some(agent_connection_output_sender) =
                                    agent_connection_output_senders
                                        .get(&agent_input_message.agent_connection_id)
                                else {
                                    error!(
                                        "Can not find agent connection output sender by id: {}",
                                        agent_input_message.agent_connection_id
                                    );
                                    return Err(ProxyError::Other(format!(
                                        "Can not find agent connection output sender by id: {}",
                                        agent_input_message.agent_connection_id
                                    )));
                                };
                                agent_connection_output_sender.clone()
                            };
                            let (transport_relay_tx, transport_relay_rx) = unbounded_channel();
                            let mut transport = TcpTransport::new(
                                agent_input_message.user_token.clone(),
                                agent_input_message.agent_connection_id.clone(),
                                transport_relay_rx,
                                agent_connection_output_sender,
                            );
                            let tunnel_id = transport.get_tunnel_id().to_string();
                            transport.connect(src_address, dst_address).await?;
                            tcp_tunnels
                                .lock()
                                .await
                                .insert(tunnel_id.clone(), transport_relay_tx);
                            if let Err(e) = transport.exec().await {
                                error!("Fail to execute transport because of error: {e:?}");
                                tcp_tunnels.lock().await.remove(&tunnel_id);
                                return Err(e);
                            };
                            tcp_tunnels.lock().await.remove(&tunnel_id);
                            Ok::<(), ProxyError>(())
                        });
                    }
                    AgentTcpPayload::Data { data } => {
                        let mut tcp_tunnels = tcp_tunnels.lock().await;
                        if let Some(transport_relay_tx) = tcp_tunnels.get(&tunnel_id) {
                            if let Err(e) = transport_relay_tx.send(data) {
                                error!("Transport [{tunnel_id}] fail to send agent tcp data for relay because of error: {e:?}");
                                tcp_tunnels.remove(&tunnel_id);
                            };
                        }
                    }
                    AgentTcpPayload::CloseRequest { tunnel_id } => {
                        debug!("Transport [{tunnel_id}] receive tcp close request from agent, close it.");
                        let mut transports = tcp_tunnels.lock().await;
                        transports.remove(&tunnel_id);
                    }
                }
            }
        });
    }

    fn handle_udp_tunnel_inbound(
        mut _udp_tunnel_inbound_rx: UnboundedReceiver<WrapperMessage>,
        _agent_connection_output_senders: Arc<
            Mutex<HashMap<String, UnboundedSender<WrapperMessage>>>,
        >,
    ) {
        tokio::spawn(async move {
            // Forward a wrapper message to a agent connection.
            todo!()
        });
    }

    fn handle_agent_connection_output(
        agent_connection_id: String,
        mut tunnel_outbount_rx: UnboundedReceiver<WrapperMessage>,
        mut agent_connection_write: AgentConnectionWrite<TcpStream>,
    ) {
        tokio::spawn(async move {
            // Spawn a task write output to agent
            while let Some(proxy_message) = tunnel_outbount_rx.recv().await {
                if let Err(e) = agent_connection_write.send(proxy_message).await {
                    error!(
                    "Fail to write data to agent connection [{agent_connection_id}] because of error: {e:?}"
                );
                    return;
                };
            }
        });
    }

    fn handle_tunnel_inbound(
        agent_connection_id: String,
        tcp_tunnel_inbound_tx: UnboundedSender<WrapperMessage>,
        udp_tunnel_inbound_tx: UnboundedSender<WrapperMessage>,
        mut agent_connection_read: AgentConnectionRead<TcpStream>,
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
                match agent_message.payload_type {
                    PayloadType::Tcp => {
                        if let Err(e) = tcp_tunnel_inbound_tx.send(agent_message) {
                            error!("Fail to forward agent input for agent connection [{agent_connection_id}] because of error: {e:?}");
                        };
                    }
                    PayloadType::Udp => {
                        if let Err(e) = udp_tunnel_inbound_tx.send(agent_message) {
                            error!("Fail to forward agent input for agent connection [{agent_connection_id}] because of error: {e:?}");
                        };
                    }
                }
            }
        });
    }
}
