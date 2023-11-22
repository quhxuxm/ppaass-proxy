mod destination;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;

use futures::StreamExt;

use log::error;

use ppaass_io::Connection as AgentConnection;
use ppaass_protocol::message::{PayloadType, WrapperMessage};
use tokio::time::timeout;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::Receiver,
};
use uuid::Uuid;

use crate::{
    config::SERVER_CONFIG, crypto::ProxyRsaCryptoFetcher, error::ProxyError, RSA_CRYPTO_FETCHER,
};

pub(crate) use self::destination::*;

pub(crate) struct Transport {
    agent_connection_id: String,
    transport_input_rx: Receiver<WrapperMessage>,
    transport_input_rx: Receiver<WrapperMessage>,
}

impl Transport {
    pub(crate) fn new(
        agent_connection_id: String,
        transport_input_rx: Receiver<WrapperMessage>,
    ) -> Transport {
        Self {
            agent_connection_id,
            transport_input_rx,
        }
    }

    pub(crate) async fn exec(self) -> Result<(), ProxyError> {
        let agent_message = match self.transport_input_rx.recv().await {
            Some(agent_message) => agent_message,
            None => {
                error!(
                    "Agent connection {} closed right after connect, close transport.",
                    self.agent_connection_id
                );
                return Ok(());
            }
        };

        if agent_message.payload_type == PayloadType::Tcp {
            let dst_tcp_handler = DstTcpHandler::new(
                self.transport_id.clone(),
                agent_connection_read,
                agent_connection_write,
            );
            dst_tcp_handler.handle(agent_message).await?;
            return Ok(());
        }

        let dest_udp_handler = DestUdpHandler::new();
        dest_udp_handler.handle_message(agent_message).await?;
        Ok(())
    }
}
