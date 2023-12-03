use anyhow::Result;

use bytes::Bytes;
use futures::StreamExt;

use futures_util::SinkExt;
use log::{debug, error};

use ppaass_protocol::message::proxy::{
    CloseTunnelCommand, InitTunnelResult, ProxyMessage, ProxyMessagePayload, RelayData,
};

use crate::destination::DstTcpConnection;
use ppaass_protocol::values::address::NetAddress;
use ppaass_protocol::values::security::{Encryption, SecureInfo};
use ppaass_protocol::values::tunnel::{Tunnel, TunnelType};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use uuid::Uuid;

use crate::error::ProxyError;
use crate::util::random_32_bytes;

pub(crate) struct TcpTransport {
    agent_edge_id: String,
    proxy_edge_id: String,
    src_address: NetAddress,
    dst_address: NetAddress,
    user_token: String,
    agent_connection_id: String,
    agent_connection_output_tx: UnboundedSender<ProxyMessage>,
    transport_relay_rx: UnboundedReceiver<Bytes>,
    dst_tcp_connection: Option<DstTcpConnection<TcpStream>>,
}

impl TcpTransport {
    pub fn new(
        agent_edge_id: String,
        proxy_edge_id: String,
        src_address: NetAddress,
        dst_address: NetAddress,
        user_token: String,
        agent_connection_id: String,
        transport_relay_rx: UnboundedReceiver<Bytes>,
        agent_connection_output_tx: UnboundedSender<ProxyMessage>,
    ) -> TcpTransport {
        Self {
            agent_edge_id,
            proxy_edge_id,
            src_address,
            dst_address,
            user_token,
            agent_connection_id,
            transport_relay_rx,
            dst_tcp_connection: None,
            agent_connection_output_tx,
        }
    }

    pub async fn connect(&mut self) -> Result<(), ProxyError> {
        debug!(
            "Transport [{}] going to connect destination: {:?}",
            self.proxy_edge_id, self.dst_address
        );
        let dst_tcp_stream = match &self.dst_address {
            NetAddress::Ip(ip_addr) => TcpStream::connect(ip_addr).await?,
            NetAddress::Domain { host, port } => TcpStream::connect((host.as_ref(), *port)).await?,
        };

        debug!(
            "Transport [{}] success connect to destination: {:?}",
            self.proxy_edge_id, self.dst_address
        );

        // Generate success proxy init response message
        let tcp_init_success_result = ProxyMessage {
            message_id: Uuid::new_v4().to_string(),
            secure_info: SecureInfo {
                user_token: self.user_token.clone(),
                encryption: Encryption::Aes(random_32_bytes()),
            },
            tunnel: Tunnel {
                agent_edge_id: self.agent_edge_id.clone(),
                proxy_edge_id: Some(self.proxy_edge_id.clone()),
                tunnel_type: TunnelType::Tcp,
            },
            payload: ProxyMessagePayload::InitTunnelResult(InitTunnelResult {
                src_address: self.src_address.clone(),
                dst_address: self.dst_address.clone(),
            }),
        };

        self.agent_connection_output_tx
            .send(tcp_init_success_result)
            .map_err(|e|ProxyError::Other(format!("Transport [{}] fail to send tcp init success response to agent connection output sender [{}] because of error: {e:?}", self.proxy_edge_id, self.agent_connection_id)))?;
        debug!(
            "Transport [{}] success send tcp init success response to agent through agent connection [{}]",
            self.proxy_edge_id,
            self.agent_connection_id
        );
        self.dst_tcp_connection = Some(DstTcpConnection::new(dst_tcp_stream, 65536));
        Ok(())
    }

    pub async fn exec(mut self) -> Result<(), ProxyError> {
        let proxy_edge_id = self.proxy_edge_id;
        let user_token = self.user_token;
        let Some(dst_tcp_connection) = self.dst_tcp_connection else {
            return Err(ProxyError::Other(format!(
                "Transport [{proxy_edge_id}] destination tcp connection still not initialized"
            )));
        };

        let (mut dst_tcp_connection_write, mut dst_tcp_connection_read) =
            dst_tcp_connection.split();
        let agent_connection_output_tx = self.agent_connection_output_tx;
        let agent_connection_id = self.agent_connection_id;
        tokio::spawn(async move {
            loop {
                let dst_data = match dst_tcp_connection_read.next().await {
                    Some(Ok(dst_data)) => dst_data,
                    Some(Err(e)) => {
                        error!("Transport [{proxy_edge_id}] fail to read dest connection because of error: {e:?}");
                        return Err(ProxyError::Other(format!("Transport [{proxy_edge_id}] fail to read dest connection because of error: {e:?}")));
                    }
                    None => {
                        debug!("Transport [{proxy_edge_id}] complete to read destination data, send tcp close request to agent.");
                        let tcp_relay_data = ProxyMessage {
                            message_id: Uuid::new_v4().to_string(),
                            secure_info: SecureInfo {
                                user_token,
                                encryption: Encryption::Aes(random_32_bytes()),
                            },
                            tunnel: Tunnel {
                                agent_edge_id: self.agent_edge_id.clone(),
                                proxy_edge_id: Some(proxy_edge_id.clone()),
                                tunnel_type: TunnelType::Tcp,
                            },
                            payload: ProxyMessagePayload::CloseTunnelCommand(CloseTunnelCommand {
                                src_address: self.src_address.clone(),
                                dst_address: self.dst_address.clone(),
                            }),
                        };
                        if let Err(e) = agent_connection_output_tx.send(tcp_relay_data) {
                            error!("Transport [{proxy_edge_id}] fail to send tcp close to agent connection [{agent_connection_id}] because of error: {e:?}");
                            return Err(ProxyError::Other(format!("Transport [{proxy_edge_id}] fail to send tcp close to agent connection [{agent_connection_id}] because of error: {e:?}")));
                        };
                        return Ok(());
                    }
                };

                let tcp_relay_data = ProxyMessage {
                    message_id: Uuid::new_v4().to_string(),
                    secure_info: SecureInfo {
                        user_token: user_token.clone(),
                        encryption: Encryption::Aes(random_32_bytes()),
                    },
                    tunnel: Tunnel {
                        agent_edge_id: self.agent_edge_id.clone(),
                        proxy_edge_id: Some(proxy_edge_id.clone()),
                        tunnel_type: TunnelType::Tcp,
                    },
                    payload: ProxyMessagePayload::RelayData(RelayData {
                        src_address: self.src_address.clone(),
                        dst_address: self.dst_address.clone(),
                        data: dst_data.freeze(),
                    }),
                };

                if let Err(e) = agent_connection_output_tx.send(tcp_relay_data) {
                    error!("Transport [{proxy_edge_id}] fail to send wrapper message to agent tcp connection [{agent_connection_id}] because of error: {e:?}");
                    return Err(ProxyError::Other(format!("Transport [{proxy_edge_id}] fail to send wrapper message to agent tcp connection [{agent_connection_id}] because of error: {e:?}")));
                };
            }
        });
        while let Some(data) = self.transport_relay_rx.recv().await {
            dst_tcp_connection_write.send(data).await?;
        }
        Ok(())
    }
}
