use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::Duration,
};

use bytes::{Bytes, BytesMut};

use futures::StreamExt as FuturesStreamExt;

use futures_util::SinkExt;

use log::{debug, error};
use ppaass_protocol::generator::PpaassMessageGenerator;
use ppaass_protocol::message::payload::tcp::{
    AgentTcpPayload, ProxyTcpInitFailureReason, ProxyTcpInitResult,
};
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryption;
use ppaass_protocol::message::{PpaassAgentMessage, PpaassAgentMessagePayload};
use scopeguard::ScopeGuard;
use tokio::net::TcpStream;

use tokio::time::timeout;
use tokio_stream::StreamExt as TokioStreamExt;
use tokio_util::codec::{BytesCodec, Framed};

use crate::codec::PpaassAgentEdgeCodec;
use crate::{config::PROXY_CONFIG, error::ProxyServerError};

pub(crate) struct TcpHandlerRequest {
    pub transport_id: String,
    pub agent_connection: Framed<TcpStream, PpaassAgentEdgeCodec>,
    pub user_token: String,
    pub src_address: PpaassUnifiedAddress,
    pub dst_address: PpaassUnifiedAddress,
    pub payload_encryption: PpaassMessagePayloadEncryption,
    pub transport_number: Arc<AtomicU64>,
}

#[derive(Default)]
pub(crate) struct TcpHandler;

impl TcpHandler {
    async fn init_dst_connection<DF>(
        transport_id: String,
        dst_address: &PpaassUnifiedAddress,
        transport_number_scopeguard: ScopeGuard<String, DF>,
    ) -> Result<(Framed<TcpStream, BytesCodec>, ScopeGuard<String, DF>), ProxyServerError>
    where
        DF: FnOnce(String),
    {
        let dst_socket_address = dst_address.to_socket_addrs()?.collect::<Vec<SocketAddr>>();
        let dst_tcp_stream = match timeout(
            Duration::from_secs(PROXY_CONFIG.get_dst_connect_timeout()),
            TcpStream::connect(dst_socket_address.as_slice()),
        )
        .await
        {
            Err(_) => {
                error!(
                    "Transport {transport_id} connect to tcp destination [{dst_address}] timeout in [{}] seconds.",
                    PROXY_CONFIG.get_dst_connect_timeout()
                );
                return Err(ProxyServerError::Other(format!(
                    "Transport {transport_id} connect to tcp destination [{dst_address}] timeout in [{}] seconds.",
                    PROXY_CONFIG.get_dst_connect_timeout()
                )));
            }
            Ok(Ok(dst_tcp_stream)) => dst_tcp_stream,
            Ok(Err(e)) => {
                error!("Transport {transport_id} connect to tcp destination [{dst_address}] fail because of error: {e:?}");
                return Err(ProxyServerError::StdIo(e));
            }
        };
        dst_tcp_stream.set_nodelay(true)?;
        dst_tcp_stream.set_linger(None)?;
        // dst_tcp_stream.writable().await?;
        // dst_tcp_stream.readable().await?;
        let dst_connection = Framed::new(dst_tcp_stream, BytesCodec::new());
        Ok((dst_connection, transport_number_scopeguard))
    }

    fn unwrap_to_raw_tcp_data(message: PpaassAgentMessage) -> Result<Bytes, ProxyServerError> {
        let PpaassAgentMessage {
            payload: PpaassAgentMessagePayload::Tcp(AgentTcpPayload::Data { content }),
            ..
        } = message
        else {
            return Err(ProxyServerError::Other(format!(
                "Fail to unwrap raw data from agent message because of invalid payload type: {message:?}"
            )));
        };
        Ok(content)
    }

    pub(crate) async fn exec(handler_request: TcpHandlerRequest) -> Result<(), ProxyServerError> {
        let TcpHandlerRequest {
            transport_id,
            mut agent_connection,
            user_token,
            src_address,
            dst_address,
            payload_encryption,
            transport_number,
        } = handler_request;
        let transport_number_scopeguard = scopeguard::guard(
            transport_id.clone(),
            move |transport_id| {
                let current_transport_number = transport_number.fetch_sub(1, Ordering::Relaxed);
                debug!("Transport {transport_id} complete, current transport number before drop: {current_transport_number}")
            },
        );

        let (dst_connection, transport_number_scopeguard) = match Self::init_dst_connection(
            transport_id.clone(),
            &dst_address,
            transport_number_scopeguard,
        )
        .await
        {
            Ok(dst_connection) => dst_connection,
            Err(e) => {
                error!(
                    "Transport {transport_id} can not connect to tcp destination [{dst_address}] because of error: {e:?}"
                );
                let tcp_init_fail_message =
                    PpaassMessageGenerator::generate_proxy_tcp_init_message(
                        user_token,
                        src_address,
                        dst_address,
                        payload_encryption,
                        ProxyTcpInitResult::Fail(
                            ProxyTcpInitFailureReason::CanNotConnectToDestination,
                        ),
                    )?;
                agent_connection.send(tcp_init_fail_message).await?;
                return Err(e);
            }
        };
        debug!("Transport {transport_id} success connect to tcp destination: {dst_address}");
        let tcp_init_success_message = PpaassMessageGenerator::generate_proxy_tcp_init_message(
            user_token.clone(),
            src_address.clone(),
            dst_address.clone(),
            payload_encryption.clone(),
            ProxyTcpInitResult::Success(transport_id.clone()),
        )?;
        agent_connection.send(tcp_init_success_message).await?;
        debug!("Transport {transport_id} sent tcp init success message to agent.");
        let (mut agent_connection_write, agent_connection_read) = agent_connection.split();
        let (mut dst_connection_write, dst_connection_read) = dst_connection.split();
        debug!(
            "Transport {transport_id} start task to relay agent and tcp destination: {dst_address}"
        );
        {
            let dst_address = dst_address.clone();
            let transport_id = transport_id.clone();
            tokio::spawn(async move {
                if let Err(e) = TokioStreamExt::map_while(agent_connection_read, |agent_message| {
                    let agent_message = agent_message.ok()?;
                    let data = Self::unwrap_to_raw_tcp_data(agent_message).ok()?;
                    Some(Ok(BytesMut::from_iter(data)))
                })
                .forward(&mut dst_connection_write)
                .await
                {
                    error!("Transport {transport_id} error happen when relay tcp data from agent to destination [{dst_address}]: {e:?}");
                }
                if let Err(e) = dst_connection_write.close().await {
                    error!("Transport {transport_id} fail to close destination connection [{dst_address}] because of error: {e:?}");
                };
            });
        }
        tokio::spawn(async move {
            let _transport_number_scopeguard = transport_number_scopeguard;
            if let Err(e) = TokioStreamExt::map_while(dst_connection_read, move |dst_message| {
                let dst_message = dst_message.ok()?;
                let tcp_data_message = PpaassMessageGenerator::generate_proxy_tcp_data_message(
                    user_token.clone(),
                    payload_encryption.clone(),
                    dst_message.freeze(),
                )
                .ok()?;
                Some(Ok(tcp_data_message))
            })
            .forward(&mut agent_connection_write)
            .await
            {
                error!("Transport {transport_id} error happen when relay tcp data from destination [{dst_address}] to agent: {e:?}", );
            }
            if let Err(e) = agent_connection_write.close().await {
                error!(
                    "Transport {transport_id} fail to close agent connection because of error: {e:?}",

                );
            };
        });
        Ok(())
    }
}
