mod destination;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;

use futures::StreamExt;

use log::error;
use ppaass_crypto::random_16_bytes;
use ppaass_io::Connection as AgentConnection;
use ppaass_protocol::message::{PayloadType, WrapperMessage};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::{
    config::SERVER_CONFIG, crypto::ProxyRsaCryptoFetcher, error::ProxyError, RSA_CRYPTO_FETCHER,
};

pub(crate) use self::destination::*;

pub(crate) struct Transport<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    agent_address: SocketAddr,
    agent_connection: AgentConnection<T, Arc<ProxyRsaCryptoFetcher>>,
    transport_id: String,
}

impl<T> Transport<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub(crate) fn new(agent_tcp_stream: T, agent_address: SocketAddr) -> Transport<T> {
        let agent_connection = AgentConnection::new(
            agent_tcp_stream,
            RSA_CRYPTO_FETCHER
                .get()
                .expect("Fail to get rsa crypto fetcher because of unknown reason.")
                .clone(),
            SERVER_CONFIG.get_compress(),
            65536,
        );
        Self {
            agent_connection,
            agent_address,
            transport_id: String::from_utf8_lossy(random_16_bytes().as_ref()).to_string(),
        }
    }

    pub(crate) async fn exec(self) -> Result<(), ProxyError> {
        let agent_connection_id = self.agent_connection.get_connection_id().to_string();
        let (agent_connection_write, mut agent_connection_read) = self.agent_connection.split();

        let agent_message = match timeout(Duration::from_secs(20), agent_connection_read.next())
            .await
        {
            Err(_) => {
                error!("Read from agent timeout: {agent_connection_id}",);
                return Err(ProxyError::Timeout(20));
            }
            Ok(Some(agent_message)) => agent_message?,
            Ok(None) => {
                error!(
                    "Agent connection {agent_connection_id} closed right after connect, close transport.");
                return Ok(());
            }
        };

        let WrapperMessage {
            user_token,
            unique_id,
            payload_type,
            payload,
            ..
        } = agent_message;

        match payload_type {
            PayloadType::Tcp => {
                let dest_tcp_handler = DestTcpHandler::new(
                    self.transport_id.clone(),
                    agent_connection_read,
                    agent_connection_write,
                );
                dest_tcp_handler
                    .handle(HandlerInput {
                        unique_id,
                        user_token,
                        payload,
                    })
                    .await?;
                Ok(())
            }
            PayloadType::Udp => {
                let dest_udp_handler = DestUdpHandler::new();
                dest_udp_handler
                    .handle_message(HandlerInput {
                        unique_id,
                        user_token,
                        payload,
                    })
                    .await?;
                Ok(())
            }
        }
    }
}
