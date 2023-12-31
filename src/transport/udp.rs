use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::SinkExt;
use futures_util::stream::SplitSink;
use ppaass_protocol::generator::PpaassMessageGenerator;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryption;
use ppaass_protocol::message::PpaassProxyMessage;
use scopeguard::ScopeGuard;
use tokio::net::TcpStream;
use tokio::{net::UdpSocket, time::timeout};
use tokio_io_timeout::TimeoutStream;
use tokio_util::codec::Framed;

use tracing::{debug, error};

use crate::codec::PpaassAgentEdgeCodec;
use crate::trace::TraceSubscriber;
use crate::{config::PROXY_CONFIG, error::ProxyServerError};

const MAX_UDP_PACKET_SIZE: usize = 65535;
const LOCAL_UDP_BIND_ADDR: &str = "0.0.0.0:0";

pub(crate) struct UdpHandlerRequest<DF: FnOnce((String, Arc<TraceSubscriber>, Arc<AtomicU64>))> {
    pub transport_id: String,
    pub agent_connection_write:
        SplitSink<Framed<TimeoutStream<TcpStream>, PpaassAgentEdgeCodec>, PpaassProxyMessage>,
    pub user_token: String,
    pub src_address: PpaassUnifiedAddress,
    pub dst_address: PpaassUnifiedAddress,
    pub udp_data: Bytes,
    pub payload_encryption: PpaassMessagePayloadEncryption,
    pub need_response: bool,
    pub transport_number_scopeguard: ScopeGuard<(String, Arc<TraceSubscriber>, Arc<AtomicU64>), DF>,
}

pub(crate) struct UdpHandler;

impl UdpHandler {
    pub(crate) async fn exec<
        DF: FnOnce((String, Arc<TraceSubscriber>, Arc<AtomicU64>)) + Send + 'static,
    >(
        handler_request: UdpHandlerRequest<DF>,
    ) -> Result<(), ProxyServerError> {
        let UdpHandlerRequest {
            transport_id,
            mut agent_connection_write,
            user_token,
            src_address,
            dst_address,
            udp_data,
            payload_encryption,
            need_response,
            transport_number_scopeguard,
            ..
        } = handler_request;
        let dst_udp_socket = UdpSocket::bind(LOCAL_UDP_BIND_ADDR).await?;
        let dst_socket_addrs = dst_address.to_socket_addrs()?;
        let dst_socket_addrs = dst_socket_addrs.collect::<Vec<SocketAddr>>();
        match timeout(
            Duration::from_secs(PROXY_CONFIG.get_dst_udp_connect_timeout()),
            dst_udp_socket.connect(dst_socket_addrs.as_slice()),
        )
        .await
        {
            Err(_) => {
                error!(
                    "Transport [{transport_id}] connect to destination udp socket [{dst_address}] timeout in [{}] seconds.",
                    PROXY_CONFIG.get_dst_udp_connect_timeout()
                );
                if let Err(e) = agent_connection_write.close().await {
                    error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
                };
                return Err(ProxyServerError::Other(format!(
                    "Transport [{transport_id}] connect to destination udp socket [{dst_address}] timeout in [{}] seconds.",
                    PROXY_CONFIG.get_dst_udp_connect_timeout()
                )));
            }
            Ok(Ok(())) => {
                debug!("Transport [{transport_id}] connect to destination udp socket [{dst_address}] success.");
            }
            Ok(Err(e)) => {
                error!("Transport [{transport_id}] connect to destination udp socket [{dst_address}] fail because of error: {e:?}");
                if let Err(e) = agent_connection_write.close().await {
                    error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
                };
                return Err(ProxyServerError::StdIo(e));
            }
        };
        if let Err(e) = dst_udp_socket.send(&udp_data).await {
            error!("Transport [{transport_id}] fail to relay agent udp data to destination udp socket [{dst_address}] because of error: {e:?}");
            if let Err(e) = agent_connection_write.close().await {
                error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
            };
            return Err(ProxyServerError::StdIo(e));
        };
        if !need_response {
            if let Err(e) = agent_connection_write.close().await {
                error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
            };
            return Ok(());
        }
        tokio::spawn(async move {
            let _transport_number_scopeguard = transport_number_scopeguard;
            let mut udp_data = BytesMut::new();
            loop {
                let mut udp_recv_buf = [0u8; MAX_UDP_PACKET_SIZE];
                let (udp_recv_buf, size) = match timeout(
                    Duration::from_secs(PROXY_CONFIG.get_dst_udp_recv_timeout()),
                    dst_udp_socket.recv(&mut udp_recv_buf),
                )
                .await
                {
                    Err(_) => {
                        debug!(
                        "Transport [{transport_id}] receive data from destination udp socket [{dst_address}] timeout in [{}] seconds.",
                        PROXY_CONFIG.get_dst_udp_recv_timeout()
                    );
                        if let Err(e) = agent_connection_write.close().await {
                            error!(
                            "Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}"
                        );
                        };
                        return Err(ProxyServerError::Other(format!(
                            "Transport [{transport_id}] receive data from destination udp socket [{dst_address}] timeout in [{}] seconds.",
                            PROXY_CONFIG.get_dst_udp_recv_timeout()
                        )));
                    }
                    Ok(Ok(0)) => {
                        debug!(
                        "Transport [{transport_id}] receive all data from destination udp socket [{dst_address}], current udp packet size: {}, last receive data size is zero",
                        udp_data.len()
                    );
                        break;
                    }
                    Ok(size) => {
                        let size = size?;
                        (&udp_recv_buf[..size], size)
                    }
                };
                udp_data.put(udp_recv_buf);
                if size < MAX_UDP_PACKET_SIZE {
                    debug!(
                    "Transport [{transport_id}] receive all data from destination udp socket [{dst_address}], current udp packet size: {}, last receive data size is: {size}",
                    udp_data.len()
                );
                    break;
                }
            }
            if udp_data.is_empty() {
                if let Err(e) = agent_connection_write.close().await {
                    error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
                };
                return Ok(());
            }
            let udp_data_message = PpaassMessageGenerator::generate_proxy_udp_data_message(
                user_token.clone(),
                payload_encryption,
                src_address.clone(),
                dst_address.clone(),
                udp_data.freeze(),
            )?;
            if let Err(e) = agent_connection_write.send(udp_data_message).await {
                error!("Transport [{transport_id}] fail to relay destination udp socket data [{dst_address}] udp data to agent because of error: {e:?}");
            };
            if let Err(e) = agent_connection_write.close().await {
                error!("Transport [{transport_id}] fail to close agent connection because of error, destination udp socket: [{dst_address}], error: {e:?}");
            };
            Ok(())
        });
        Ok(())
    }
}
