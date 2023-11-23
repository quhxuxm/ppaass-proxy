use crate::{
    config::SERVER_CONFIG,
    error::ProxyError,
    transport::Transport,
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
use ppaass_protocol::message::{AgentTcpPayload, PayloadType, WrapperMessage};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
};
use uuid::Uuid;

/// The ppaass proxy server.
pub(crate) struct Server {
    /// The container of every agent connection, the key will be the
    /// agent connection id, the value is the output sender of the connection
    raw_agent_connection_output_repo: Arc<Mutex<HashMap<String, Sender<WrapperMessage>>>>,
    tcp_transports: Arc<Mutex<HashMap<String, Sender<Bytes>>>>,
}

impl Server {
    pub(crate) fn new() -> Self {
        Self {
            raw_agent_connection_output_repo: Default::default(),
            tcp_transports: Default::default(),
        }
    }
    /// Accept agent connection
    async fn accept_raw_agent_tcp_stream(
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
        let (agent_tcp_input_queue_tx, agent_tcp_input_queue_rx) =
            channel::<AgentInputTcpMessage>(65536);
        let (agent_udp_input_queue_tx, agent_udp_input_queue_rx) =
            channel::<AgentInputUdpMessage>(65536);

        Self::handle_agent_tcp_input_queue(
            agent_tcp_input_queue_rx,
            self.raw_agent_connection_output_repo.clone(),
            self.tcp_transports.clone(),
        );
        Self::handle_agent_udp_input_queue(
            agent_udp_input_queue_rx,
            self.raw_agent_connection_output_repo.clone(),
        );

        // Start the loop for accept agent connection
        loop {
            let (raw_agent_tcp_stream, agent_address) =
                match Self::accept_raw_agent_tcp_stream(&tcp_listener).await {
                    Ok(accept_result) => accept_result,
                    Err(e) => {
                        error!(
                            "Proxy server fail to accept agent connection because of error: {e:?}"
                        );
                        continue;
                    }
                };
            let raw_agent_connection = AgentConnection::new(
                raw_agent_tcp_stream,
                RSA_CRYPTO_FETCHER
                    .get()
                    .expect("Fail to get rsa crypto fetcher because of unknown reason.")
                    .clone(),
                SERVER_CONFIG.get_compress(),
                65536,
            );
            let raw_agent_connection_id = Uuid::new_v4().to_string();

            debug!("Proxy server success accept agent connection on address: {agent_address}, create new raw agent connection: {raw_agent_connection_id}");
            let (raw_agent_connection_write, raw_agent_connection_read) =
                raw_agent_connection.split();
            let (raw_agent_connection_output_tx, raw_agent_connection_output_rx) =
                channel::<WrapperMessage>(2048);

            // Start the task to handle the raw agent tcp connection output
            Self::handle_raw_agent_connection_output(
                raw_agent_connection_id.clone(),
                raw_agent_connection_output_rx,
                raw_agent_connection_write,
            );

            // Start the task to handle the raw agent tcp connection input
            Self::handle_raw_agent_connection_input(
                raw_agent_connection_id.clone(),
                agent_tcp_input_queue_tx.clone(),
                agent_udp_input_queue_tx.clone(),
                raw_agent_connection_read,
            );

            let mut raw_agent_connection_output_repo =
                self.raw_agent_connection_output_repo.lock().await;
            raw_agent_connection_output_repo.insert(
                raw_agent_connection_id.clone(),
                raw_agent_connection_output_tx,
            );
        }
    }

    fn handle_agent_tcp_input_queue(
        mut agent_tcp_input_queue_rx: Receiver<AgentInputTcpMessage>,
        raw_agent_connection_output_repo: Arc<Mutex<HashMap<String, Sender<WrapperMessage>>>>,
        transports: Arc<Mutex<HashMap<String, Sender<Bytes>>>>,
    ) {
        tokio::spawn(async move {
            // Forward a wrapper message to a agent connection.
            while let Some(agent_input_message) = agent_tcp_input_queue_rx.recv().await {
                match agent_input_message.payload {
                    AgentTcpPayload::InitRequest {
                        src_address,
                        dst_address,
                    } => {
                        if let Some(raw_agent_connection_output_tx) =
                            raw_agent_connection_output_repo
                                .lock()
                                .await
                                .get(&agent_input_message.raw_agent_connection_id)
                        {
                            let raw_agent_connection_output_tx =
                                raw_agent_connection_output_tx.clone();
                            let transports = transports.clone();
                            tokio::spawn(async move {
                                let (transport_relay_tx, transport_relay_rx) = channel(65536);
                                let mut transport = Transport::new(
                                    agent_input_message.raw_agent_connection_id.clone(),
                                    agent_input_message.user_token.clone(),
                                    transport_relay_rx,
                                    raw_agent_connection_output_tx.clone(),
                                );
                                let transport_id = transport.get_transport_id().to_string();
                                transport.connect(src_address, dst_address).await?;
                                transports
                                    .lock()
                                    .await
                                    .insert(transport_id.clone(), transport_relay_tx);
                                if let Err(e) = transport.exec().await {
                                    error!("Fail to execute transport because of error: {e:?}");
                                    transports.lock().await.remove(&transport_id);
                                    return Err(e);
                                };
                                transports.lock().await.remove(&transport_id);
                                Ok::<(), ProxyError>(())
                            });
                        }
                    }
                    AgentTcpPayload::Data {
                        connection_id,
                        data,
                    } => {
                        let mut transports = transports.lock().await;
                        if let Some(transport_relay_tx) = transports.get(&connection_id) {
                            if let Err(e) = transport_relay_tx.send(data).await {
                                error!("Transport [{connection_id}] fail to send agent tcp data for relay because of error: {e:?}");
                                transports.remove(&connection_id);
                            };
                        }
                    }
                    AgentTcpPayload::CloseRequest { connection_id } => {
                        debug!("Transport [{connection_id}] receive tcp close request from agent, close it.");
                        let mut transports = transports.lock().await;
                        transports.remove(&connection_id);
                    }
                }
            }
        });
    }

    fn handle_agent_udp_input_queue(
        mut agent_udp_input_queue_rx: Receiver<AgentInputUdpMessage>,
        raw_agent_connection_output_repo: Arc<Mutex<HashMap<String, Sender<WrapperMessage>>>>,
    ) {
        tokio::spawn(async move {
            // Forward a wrapper message to a agent connection.
            while let Some(agent_input_message) = agent_udp_input_queue_rx.recv().await {}
        });
    }

    fn handle_raw_agent_connection_output(
        raw_agent_connection_id: String,
        mut raw_agent_connection_output_rx: Receiver<WrapperMessage>,
        mut raw_agent_connection_write: AgentConnectionWrite<TcpStream>,
    ) {
        tokio::spawn(async move {
            // Spawn a task write output to agent
            while let Some(wrapper_message) = raw_agent_connection_output_rx.recv().await {
                if let Err(e) = raw_agent_connection_write.send(wrapper_message).await {
                    error!(
                    "Fail to write data to agent connection [{raw_agent_connection_id}] because of error: {e:?}"
                );
                    return;
                };
            }
        });
    }

    fn handle_raw_agent_connection_input(
        raw_agent_connection_id: String,
        agent_tcp_input_queue_tx: Sender<AgentInputTcpMessage>,
        agent_udp_input_queue_tx: Sender<AgentInputUdpMessage>,
        mut raw_agent_connection_read: AgentConnectionRead<TcpStream>,
    ) {
        tokio::spawn(async move {
            // Spawn a task read input from agent
            while let Some(wrapper_message) = raw_agent_connection_read.next().await {
                let wrapper_message = match wrapper_message {
                    Ok(message) => message,
                    Err(e) => {
                        error!("Fail to read data from agent connection [{raw_agent_connection_id}] because of error: {e:?}");
                        return;
                    }
                };
                match wrapper_message.payload_type {
                    PayloadType::Tcp => {
                        let agent_input_tcp_message = AgentInputTcpMessage {
                            raw_agent_connection_id: raw_agent_connection_id.clone(),
                            unique_id: wrapper_message.unique_id,
                            user_token: wrapper_message.user_token,
                            payload: match wrapper_message.payload.try_into() {
                                Ok(payload) => payload,
                                Err(e) => {
                                    error!("Fail to convert agent message tcp payload for agent connection [{raw_agent_connection_id}] because of error: {e:?}");
                                    return;
                                }
                            },
                        };
                        if let Err(e) = agent_tcp_input_queue_tx.send(agent_input_tcp_message).await
                        {
                            error!("Fail to forward agent input for agent connection [{raw_agent_connection_id}] because of error: {e:?}");
                        };
                    }
                    PayloadType::Udp => {
                        let agent_input_udp_message = AgentInputUdpMessage {
                            raw_agent_connection_id: raw_agent_connection_id.clone(),
                            unique_id: wrapper_message.unique_id,
                            user_token: wrapper_message.user_token,
                            payload: match wrapper_message.payload.try_into() {
                                Ok(payload) => payload,
                                Err(e) => {
                                    error!("Fail to convert agent message udp payload for agent connection [{raw_agent_connection_id}] because of error: {e:?}");
                                    return;
                                }
                            },
                        };
                        if let Err(e) = agent_udp_input_queue_tx.send(agent_input_udp_message).await
                        {
                            error!("Fail to forward agent input for agent connection [{raw_agent_connection_id}] because of error: {e:?}");
                        };
                    }
                }
            }
        });
    }
}
