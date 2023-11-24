mod destination;

use anyhow::Result;

use bytes::Bytes;
use futures::StreamExt;

use futures_util::SinkExt;
use log::{debug, error};

use ppaass_protocol::message::{NetAddress, WrapperMessage};
use tokio::sync::mpsc::Sender;
use tokio::{net::TcpStream, sync::mpsc::Receiver};
use uuid::Uuid;

use crate::error::ProxyError;

pub(crate) use self::destination::*;

pub(crate) struct TcpTransport {
    tunnel_id: String,
    agent_connection_id: String,
    user_token: String,
    transport_relay_rx: Receiver<Bytes>,
    agent_connection_output_tx: Sender<WrapperMessage>,
    dst_tcp_connection: Option<DstTcpConnection<TcpStream>>,
}

impl TcpTransport {
    pub fn new(
        agent_connection_id: String,
        user_token: String,
        transport_relay_rx: Receiver<Bytes>,
        agent_connection_output_tx: Sender<WrapperMessage>,
    ) -> TcpTransport {
        Self {
            agent_connection_id,
            user_token,
            tunnel_id: Uuid::new_v4().to_string(),
            transport_relay_rx,
            agent_connection_output_tx,
            dst_tcp_connection: None,
        }
    }

    pub fn get_tunnel_id(&self) -> &str {
        &self.tunnel_id
    }

    pub async fn connect(
        &mut self,
        src_address: NetAddress,
        dst_address: NetAddress,
    ) -> Result<(), ProxyError> {
        debug!(
            "Transport [{}] going to connect destination: {dst_address:?}",
            self.tunnel_id
        );
        let dst_tcp_stream = match &dst_address {
            NetAddress::Ip(ip_addr) => TcpStream::connect(ip_addr).await?,
            NetAddress::Domain { host, port } => TcpStream::connect((host.as_ref(), *port)).await?,
        };

        debug!(
            "Transport [{}] success connect to destination: {dst_address:?}",
            self.tunnel_id
        );

        // Generate success proxy init response message
        let tcp_init_success_response = ppaass_protocol::new_proxy_tcp_init_success_response(
            self.tunnel_id.clone(),
            self.user_token.clone(),
            src_address,
            dst_address,
        )?;
        self.agent_connection_output_tx
            .send(tcp_init_success_response)
            .await.map_err(|e|ProxyError::Other(format!("Transport [{}] fail to send tcp init success response to raw agent connection output sender because of error: {e:?}", self.tunnel_id)))?;
        debug!(
            "Transport [{}] success send tcp init success response to agent through agent connection [{}]",
            self.tunnel_id, self.agent_connection_id
        );
        self.dst_tcp_connection = Some(DstTcpConnection::new(dst_tcp_stream, 65536));
        Ok(())
    }

    pub async fn exec(mut self) -> Result<(), ProxyError> {
        let tunnel_id = self.tunnel_id;
        let user_token = self.user_token;
        let Some(dst_tcp_connection) = self.dst_tcp_connection else {
            return Err(ProxyError::Other(format!(
                "Transport [{tunnel_id}] destination tcp connection still not initialized"
            )));
        };
        let agent_connection_output_tx = self.agent_connection_output_tx;
        let (mut dst_tcp_connection_write, mut dst_tcp_connection_read) =
            dst_tcp_connection.split();
        tokio::spawn(async move {
            loop {
                let dst_data = match dst_tcp_connection_read.next().await {
                    Some(Ok(dst_data)) => dst_data,
                    Some(Err(e)) => {
                        error!("Transport [{tunnel_id}] fail to read dest connection because of error: {e:?}");
                        return;
                    }
                    None => {
                        debug!("Transport [{tunnel_id}] complete to read destination data, send tcp close request to agent.");
                        let wrapper_message = match ppaass_protocol::new_proxy_tcp_close_request(
                            user_token.clone(),
                            tunnel_id.clone(),
                        ) {
                            Ok(wrapper_message) => wrapper_message,
                            Err(e) => {
                                error!("Transport [{tunnel_id}] fail to generate proxy tcp close request message because of error: {e:?}");
                                return;
                            }
                        };
                        if let Err(e) = agent_connection_output_tx.send(wrapper_message).await {
                            error!("Transport [{tunnel_id}] fail to send tcp close to raw agent tcp connection because of error: {e:?}");
                            return;
                        };
                        return;
                    }
                };
                let wrapper_message = match ppaass_protocol::new_proxy_tcp_data(
                    user_token.clone(),
                    tunnel_id.clone(),
                    dst_data.freeze(),
                ) {
                    Ok(wrapper_message) => wrapper_message,
                    Err(e) => {
                        error!("Transport [{tunnel_id}] fail to generate proxy data message because of error: {e:?}");
                        return;
                    }
                };
                if let Err(e) = agent_connection_output_tx.send(wrapper_message).await {
                    error!("Transport [{tunnel_id}] fail to send wrapper message to raw agent tcp connection because of error: {e:?}");
                    return;
                };
            }
        });
        while let Some(data) = self.transport_relay_rx.recv().await {
            dst_tcp_connection_write.send(data).await?;
        }
        Ok(())
    }
}
