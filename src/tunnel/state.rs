use super::{AgentConnectionRead, AgentConnectionWrite};
use bytes::Bytes;
use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_protocol::message::values::{
    address::PpaassUnifiedAddress, encryption::PpaassMessagePayloadEncryption,
};
use std::fmt::Display;
use std::fmt::Result as FmtResult;
use std::marker::PhantomData;
use tokio::net::UdpSocket;
use tokio_io_timeout::TimeoutStream;
use tokio_tfo::TfoStream;
use tokio_util::codec::{BytesCodec, Framed};
/// The marker trait for tunnel state.
pub trait TunnelState {}
/// The initial state of the tunnel
pub struct InitState;
impl TunnelState for InitState {}
impl Display for InitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "INIT")
    }
}
/// The agent accepted state of the tunnel
pub enum AgentAcceptedState<'crypto, F>
where
    F: RsaCryptoFetcher + Clone + 'crypto,
{
    Tcp {
        /// The user token of the tunnel
        user_token: String,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead<F>,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<F>,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        _marker: &'crypto PhantomData<()>,
    },
    Udp {
        /// The user token of the tunnel
        user_token: String,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<F>,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead<F>,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        /// The udp data of the udp packet
        udp_data: Bytes,
        _marker: &'crypto PhantomData<()>,
    },
}
impl<'crypto, F> TunnelState for AgentAcceptedState<'crypto, F> where
    F: RsaCryptoFetcher + Clone + 'crypto
{
}
impl<'crypto, F> Display for AgentAcceptedState<'crypto, F>
where
    F: RsaCryptoFetcher + Clone + 'crypto,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "AGENT_ACCEPTED")
    }
}
/// The destination connected state of the tunnel
pub enum DestConnectedState<'crypto, F>
where
    F: RsaCryptoFetcher + Clone + 'crypto,
{
    Tcp {
        /// The user token of the tunnel
        user_token: String,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead<F>,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<F>,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        dst_connection: Framed<TimeoutStream<TfoStream>, BytesCodec>,
        _marker: &'crypto PhantomData<()>,
    },
    Udp {
        /// The user token of the tunnel
        user_token: String,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<F>,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead<F>,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        /// The destination udp socket
        dst_udp_socket: UdpSocket,
        /// The udp data of the udp packet
        udp_data: Bytes,
        _marker: &'crypto PhantomData<()>,
    },
}
impl<'crypto, F> TunnelState for DestConnectedState<'crypto, F> where
    F: RsaCryptoFetcher + Clone + 'crypto
{
}
impl<'crypto, F> Display for DestConnectedState<'crypto, F>
where
    F: RsaCryptoFetcher + Clone + 'crypto,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "DESTINATION_CONNECTED")
    }
}
/// The relay state of the tunnel
pub struct RelayState;
impl TunnelState for RelayState {}
impl Display for RelayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "RELAY")
    }
}
