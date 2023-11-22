use crate::{
    config::SERVER_CONFIG, error::ProxyError, transport::Transport, types::AgentInputMessage,
    RSA_CRYPTO_FETCHER,
};

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info};

use ppaass_io::Connection as AgentConnection;
use ppaass_protocol::message::WrapperMessage;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{channel, Sender},
        Mutex,
    },
};
use uuid::Uuid;

/// The ppaass proxy server.
pub(crate) struct Server {
    /// The container of every agent connection, the key will be the
    /// agent connection id, the value is the output sender of the connection
    agent_connections: Arc<Mutex<HashMap<String, Sender<WrapperMessage>>>>,
}

impl Server {
    pub(crate) fn new() -> Self {
        Self {
            agent_connections: Default::default(),
        }
    }
    /// Accept agent connection
    async fn accept_raw_agent_connection(
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
        let (global_agent_input_tx, mut global_agent_input_rx) =
            channel::<AgentInputMessage>(65536);
        {
            let agent_connections = self.agent_connections.clone();
            tokio::spawn(async move {
                // Forward a wrapper message to a agent connection.
                while let Some(agent_input_message) = global_agent_input_rx.recv().await {
                    let agent_connections = agent_connections.lock().await;
                    let agent_connection =
                        agent_connections.get(&agent_input_message.agent_connection_id);
                    if let Some(ref transport_input_tx) = agent_connection {
                        if let Err(e) = transport_input_tx
                            .send(agent_input_message.wrapper_message)
                            .await
                        {
                            error!("Fail to send wrapper message to agent connection [{}] because of error: {e:?}", agent_input_message.agent_connection_id);
                        };
                    }
                }
            });
        }
        loop {
            // Start the loop for accept agent connection
            let (agent_tcp_stream, agent_address) =
                match Self::accept_raw_agent_connection(&tcp_listener).await {
                    Ok(accept_result) => accept_result,
                    Err(e) => {
                        error!(
                            "Proxy server fail to accept agent connection because of error: {e:?}"
                        );
                        continue;
                    }
                };

            let agent_connection_id = Uuid::new_v4().to_string();
            let agent_connection = AgentConnection::new(
                agent_tcp_stream,
                RSA_CRYPTO_FETCHER
                    .get()
                    .expect("Fail to get rsa crypto fetcher because of unknown reason.")
                    .clone(),
                SERVER_CONFIG.get_compress(),
                65536,
            );
            debug!("Proxy server success accept agent connection on address: {agent_address}, create new agent connection: {agent_connection_id}");
            let (mut agent_connection_write, mut agent_connection_read) = agent_connection.split();
            let (agent_connection_output_tx, mut agent_connection_output_rx) =
                channel::<WrapperMessage>(2048);
            let (transport_input_tx, mut transport_input_rx) = channel::<WrapperMessage>(2048);

            self.agent_connections
                .lock()
                .await
                .entry(agent_connection_id.clone())
                .or_insert(transport_input_tx);
            {
                let agent_connection_id = agent_connection_id.clone();
                tokio::spawn(async move {
                    // Spawn a task write output to agent
                    while let Some(wrapper_message) = agent_connection_output_rx.recv().await {
                        if let Err(e) = agent_connection_write.send(wrapper_message).await {
                            error!(
                                "Fail to write data to agent connection [{agent_connection_id}] because of error: {e:?}"
                            );
                            return;
                        };
                    }
                });
            }

            {
                let global_agent_input_tx = global_agent_input_tx.clone();
                let agent_connection_id = agent_connection_id.clone();
                tokio::spawn(async move {
                    // Spawn a task read input from agent
                    while let Some(wrapper_message) = agent_connection_read.next().await {
                        let wrapper_message = match wrapper_message {
                            Ok(message) => message,
                            Err(e) => {
                                error!("Fail to read data from agent connection [{agent_connection_id}] because of error: {e:?}");
                                return;
                            }
                        };
                        if let Err(e) = global_agent_input_tx
                            .send(AgentInputMessage {
                                agent_connection_id: agent_connection_id.clone(),
                                wrapper_message,
                            })
                            .await
                        {
                            error!("Fail to forward agent input for agent connection [{agent_connection_id}] because of error: {e:?}");
                        };
                    }
                });
            }

            tokio::spawn(async move {
                let transport = Transport::new(agent_connection_id.clone(), transport_input_rx);
                transport.exec().await?;
                debug!("Complete execute transport on agent connection [{agent_connection_id}].");
                Ok::<_, ProxyError>(())
            });
        }
    }
}
