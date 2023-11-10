use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use futures::StreamExt;
use log::error;
use ppaass_io::Connection;
use ppaass_protocol::message::NetAddress;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::{config::SERVER_CONFIG, crypto::ProxyRsaCryptoFetcher, error::ProxyError};

pub(crate) struct Transport<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    agent_connection: Connection<T, ProxyRsaCryptoFetcher>,
}

impl<T> Transport<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub(crate) fn new(agent_tcp_stream: T, agent_address: NetAddress) -> Transport<T> {
        let agent_connection = Connection::new(
            agent_tcp_stream,
            &*RSA_CRYPTO,
            SERVER_CONFIG.get_compress(),
            SERVER_CONFIG.get_agent_recive_buffer_size(),
        );
        Self { agent_connection }
    }

    pub(crate) async fn exec(mut self) -> Result<(), ProxyError> {
        //Read the first message from agent connection
        let agent_message = match timeout(
            Duration::from_secs(PROXY_CONFIG.get_agent_relay_timeout()),
            self.agent_connection.next(),
        )
        .await
        {
            Err(_) => {
                error!(
                    "Read from agent timeout: {:?}",
                    self.agent_connection.get_connection_id()
                );
                return Err(ProxyServerError::Timeout(
                    PROXY_CONFIG.get_agent_relay_timeout(),
                ));
            }
            Ok(Some(agent_message)) => agent_message?,
            Ok(None) => {
                error!(
                    "Transport {} closed in agent side, close proxy side also.",
                    self.agent_connection.get_connection_id()
                );
                return Ok(());
            }
        };
        let PpaassAgentMessage {
            user_token,
            id: agent_tcp_init_message_id,
            payload: PpaassAgentMessagePayload { protocol, data },
            ..
        } = agent_message;
        let payload_encryption = ProxyServerPayloadEncryptionSelector::select(
            &user_token,
            Some(Bytes::from(generate_uuid().into_bytes())),
        );
        match protocol {
            PpaassMessageAgentProtocol::Tcp(payload_type) => {
                if PpaassMessageAgentTcpPayloadType::Init != payload_type {
                    return Err(ProxyServerError::Other(format!(
                        "Invalid tcp init payload type from agent message: {:?}",
                        payload_type
                    )));
                }
                let AgentTcpInit {
                    src_address,
                    dst_address,
                } = data.try_into()?;
                // Tcp handler will block the thread and continue to
                // handle the agent connection in a loop
                TcpHandler::exec(
                    self.agent_connection,
                    agent_tcp_init_message_id,
                    user_token,
                    src_address,
                    dst_address,
                    payload_encryption,
                )
                .await?;
                Ok(())
            }
            PpaassMessageAgentProtocol::Udp(payload_type) => {
                if PpaassMessageAgentUdpPayloadType::Data != payload_type {
                    return Err(ProxyServerError::Other(format!(
                        "Invalid udp data payload type from agent message: {:?}",
                        payload_type
                    )));
                }
                let AgentUdpData {
                    src_address,
                    dst_address,
                    data: udp_raw_data,
                    need_response,
                    ..
                } = data.try_into()?;
                // Udp handler will block the thread and continue to
                // handle the agent connection in a loop
                UdpHandler::exec(
                    self.agent_connection,
                    user_token,
                    src_address,
                    dst_address,
                    udp_raw_data,
                    payload_encryption,
                    need_response,
                )
                .await?;
                Ok(())
            }
        }
    }
}
