use std::{collections::VecDeque, sync::Arc};

use bytes::BytesMut;

use futures_util::{SinkExt, StreamExt};
use log::{debug, error};

use ppaass_protocol::message::{
    AgentTcpPayload, NetAddress, UnwrappedAgentTcpPayload, WrapperMessage,
};
use ppaass_protocol::unwrap_agent_tcp_payload;
use pretty_hex::pretty_hex;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{Mutex, Notify},
};

use crate::{
    error::ProxyError,
    transport::destination::tcp::connection::DstTcpConnection,
    types::{AgentConnectionRead, AgentConnectionWrite},
};

use super::connection::{DstConnectionRead, DstConnectionWrite};

pub(crate) struct DstTcpHandler<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    agent_connection_read: AgentConnectionRead<T>,
    agent_connection_write: AgentConnectionWrite<T>,
    transport_id: String,
    agent_recv_buf: Arc<Mutex<VecDeque<Option<Vec<u8>>>>>,
    agent_recv_buf_notifier: Arc<Notify>,
    dst_recv_buf: Arc<Mutex<VecDeque<Option<Vec<u8>>>>>,
    dst_recv_buf_notifier: Arc<Notify>,
}

impl<T> DstTcpHandler<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub fn new(
        transport_id: String,
        agent_connection_read: AgentConnectionRead<T>,
        agent_connection_write: AgentConnectionWrite<T>,
    ) -> Self {
        Self {
            transport_id,
            agent_connection_read,
            agent_connection_write,
            agent_recv_buf: Arc::new(Mutex::new(VecDeque::with_capacity(65536))),
            dst_recv_buf: Arc::new(Mutex::new(VecDeque::with_capacity(65536))),
            agent_recv_buf_notifier: Arc::new(Notify::new()),
            dst_recv_buf_notifier: Arc::new(Notify::new()),
        }
    }

    pub async fn handle(mut self, input: WrapperMessage) -> Result<(), ProxyError> {
        let UnwrappedAgentTcpPayload {
            user_token,
            payload,
            ..
        } = unwrap_agent_tcp_payload(input)?;
        let dest_tcp_connection = match payload {
            AgentTcpPayload::Data { connection_id, .. } => {
                // The first agent message should be init request but not the data.
                return Err(ProxyError::Other(format!("The first agent message should be init request but not the data, transport: {}, agent connection: {connection_id}", self.transport_id)));
            }
            AgentTcpPayload::InitRequest {
                src_address,
                dst_address,
            } => {
                // The first agent agent message is init request
                // which is used for initialize destination tcp connection
                debug!("Going to connect destination: {dst_address:?}");
                let dest_tcp_stream = match &dst_address {
                    NetAddress::Ip(ip_addr) => TcpStream::connect(ip_addr).await?,
                    NetAddress::Domain { host, port } => {
                        TcpStream::connect((host.as_ref(), *port)).await?
                    }
                };

                debug!("Success connect to destination: {dst_address:?}");

                // Generate success proxy init response message
                let tcp_init_success_response =
                    ppaass_protocol::new_proxy_tcp_init_success_response(
                        self.transport_id.clone(),
                        user_token.clone(),
                        src_address,
                        dst_address,
                    )?;
                self.agent_connection_write
                    .send(tcp_init_success_response)
                    .await?;
                DstTcpConnection::new(dest_tcp_stream, 65536)
            }
        };
        let (dest_connection_write, dest_connection_read) = dest_tcp_connection.split();

        Self::start_receive_agent_message(
            self.transport_id.clone(),
            self.agent_recv_buf.clone(),
            self.agent_recv_buf_notifier.clone(),
            self.agent_connection_read,
        );

        Self::start_receive_dst_message(
            self.transport_id.clone(),
            self.dst_recv_buf.clone(),
            self.dst_recv_buf_notifier.clone(),
            dest_connection_read,
        );

        Self::start_relay_agent_to_dst(
            self.transport_id.clone(),
            self.agent_recv_buf.clone(),
            self.agent_recv_buf_notifier.clone(),
            dest_connection_write,
        );

        Self::start_relay_dst_to_agent(
            self.transport_id.clone(),
            user_token,
            self.dst_recv_buf.clone(),
            self.dst_recv_buf_notifier.clone(),
            self.agent_connection_write,
        );

        Ok(())
    }

    /// Read the dest receive buffer to agent
    fn start_relay_dst_to_agent(
        transport_id: String,
        user_token: String,
        dst_recv_buf: Arc<Mutex<VecDeque<Option<Vec<u8>>>>>,
        dst_recv_buf_notifier: Arc<Notify>,
        mut agent_connection_write: AgentConnectionWrite<T>,
    ) {
        tokio::spawn(async move {
            let mut complete = false;
            loop {
                let data = {
                    dst_recv_buf_notifier.notified().await;
                    let mut dst_recv_buf = dst_recv_buf.lock().await;
                    let mut data = BytesMut::new();
                    while let Some(item) = dst_recv_buf.pop_front() {
                        if let Some(item) = item {
                            data.extend_from_slice(&item);
                            continue;
                        }
                        complete = true;
                        break;
                    }
                    data
                };

                debug!(
                    "<<<< Transport [{transport_id}] going to relay destination message to agent:\n{}\n",
                    pretty_hex(&data)
                );
                let wrapper_message = match ppaass_protocol::new_proxy_tcp_data(
                    user_token.clone(),
                    transport_id.clone(),
                    data.freeze(),
                ) {
                    Ok(wrapper_message) => wrapper_message,
                    Err(e) => {
                        error!("Transport [{transport_id}] fail to generate proxy data message because of error: {e:?}");
                        return;
                    }
                };

                if let Err(e) = agent_connection_write.send(wrapper_message).await {
                    error!("Transport [{transport_id}] fail to send agent recv buffer data to destination because of error: {e:?}");
                    return;
                };
                if complete {
                    break;
                }
            }
        });
    }

    /// Read the agent receive buffer to destination
    fn start_relay_agent_to_dst(
        transport_id: String,
        agent_recv_buf: Arc<Mutex<VecDeque<Option<Vec<u8>>>>>,
        agent_recv_buf_notifier: Arc<Notify>,
        mut dst_connection_write: DstConnectionWrite,
    ) {
        tokio::spawn(async move {
            let mut complete = false;
            loop {
                let data = {
                    agent_recv_buf_notifier.notified().await;
                    let mut agent_recv_buf = agent_recv_buf.lock().await;
                    let mut data = BytesMut::new();
                    while let Some(item) = agent_recv_buf.pop_front() {
                        if let Some(item) = item {
                            data.extend_from_slice(&item);
                            continue;
                        }
                        complete = true;
                        break;
                    }

                    data
                };
                debug!(
                    ">>>> Transport [{transport_id}] going to relay agent message to destination:\n{}\n",
                    pretty_hex(&data)
                );
                if let Err(e) = dst_connection_write.send(data.freeze()).await {
                    error!("Transport [{transport_id}] fail to send agent recv buffer data to destination because of error: {e:?}");
                    return;
                };
                if complete {
                    break;
                }
            }
        });
    }

    /// Read the agent data to receive buffer
    fn start_receive_dst_message(
        transport_id: String,
        dst_recv_buf: Arc<Mutex<VecDeque<Option<Vec<u8>>>>>,
        dst_recv_buf_notifier: Arc<Notify>,
        mut dst_connection_read: DstConnectionRead,
    ) {
        tokio::spawn(async move {
            loop {
                let dst_message = match dst_connection_read.next().await {
                    Some(Ok(dst_message)) => dst_message,
                    Some(Err(e)) => {
                        error!(
                            "Transport [{transport_id}] fail to read dest connection because of error: {e:?}"
                        );
                        let mut dst_recv_buf = dst_recv_buf.lock().await;
                        dst_recv_buf.push_back(None);
                        dst_recv_buf_notifier.notify_waiters();
                        return;
                    }
                    None => {
                        debug!("Transport [{transport_id}] complete to read destination data.");
                        let mut dst_recv_buf = dst_recv_buf.lock().await;
                        dst_recv_buf.push_back(None);
                        dst_recv_buf_notifier.notify_waiters();
                        return;
                    }
                };
                debug!(
                    "<<<< Transport [{transport_id}] receive destination message:\n{}\n",
                    pretty_hex(&dst_message)
                );
                let mut dst_recv_buf = dst_recv_buf.lock().await;
                dst_recv_buf.push_back(Some(dst_message.to_vec()));
                dst_recv_buf_notifier.notify_waiters();
            }
        });
    }

    /// Read the agent data to receive buffer
    fn start_receive_agent_message(
        transport_id: String,
        agent_recv_buf: Arc<Mutex<VecDeque<Option<Vec<u8>>>>>,
        agent_recv_buf_notifier: Arc<Notify>,
        mut agent_connection_read: AgentConnectionRead<T>,
    ) {
        tokio::spawn(async move {
            loop {
                let wrapper_message = match agent_connection_read.next().await {
                    Some(Ok(wrapper_message)) => wrapper_message,
                    Some(Err(e)) => {
                        error!("Transport [{transport_id}] fail to read agent connection because of error: {e:?}");
                        let mut agent_recv_buf = agent_recv_buf.lock().await;
                        agent_recv_buf.push_back(None);
                        agent_recv_buf_notifier.notify_waiters();
                        return;
                    }
                    None => {
                        debug!("Transport [{transport_id}] complete to read from agent.");
                        let mut agent_recv_buf = agent_recv_buf.lock().await;
                        agent_recv_buf.push_back(None);
                        agent_recv_buf_notifier.notify_waiters();
                        return;
                    }
                };

                let UnwrappedAgentTcpPayload {
                    payload: agent_tcp_payload,
                    ..
                } = match unwrap_agent_tcp_payload(wrapper_message) {
                    Ok(agent_tcp_payload) => agent_tcp_payload,
                    Err(e) => {
                        error!("Transport [{transport_id}] fail to unwrap agent tcp message because of error: {e:?}");
                        return;
                    }
                };
                let AgentTcpPayload::Data { data, .. } = agent_tcp_payload else {
                    error!("Transport [{transport_id}] incoming message is not a Data message.");
                    return;
                };
                debug!(
                    ">>>> Transport [{transport_id}] receive agent message:\n{}\n",
                    pretty_hex(&data)
                );
                let mut agent_recv_buf = agent_recv_buf.lock().await;
                agent_recv_buf.push_back(Some(data.to_vec()));
                agent_recv_buf_notifier.notify_waiters();
            }
        });
    }
}
