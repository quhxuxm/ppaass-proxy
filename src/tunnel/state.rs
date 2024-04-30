use std::fmt::Display;
use std::fmt::Result as FmtResult;
use bytes::Bytes;
use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_protocol::message::values::{
    address::PpaassUnifiedAddress, encryption::PpaassMessagePayloadEncryption,
};
use tokio::net::{TcpStream, UdpSocket};
use tokio_io_timeout::TimeoutStream;
use tokio_util::codec::{BytesCodec, Framed};
use super::{AgentConnectionRead, AgentConnectionWrite};
/// The marker trait for tunnel state.
pub(crate) trait TunnelState {}
/// The initial state of the tunnel
pub(crate) struct InitState;
impl TunnelState for InitState {}
impl Display for InitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "INIT")
    }
}
/// The agent accepted state of the tunnel
pub(crate) enum AgentAcceptedState<'crypto, F>
where
    F: RsaCryptoFetcher + Clone,
{
    Tcp {
        /// The user token of the tunnel
        user_token: String,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead<&'crypto F>,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<&'crypto F>,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
    },
    Udp {
        /// The user token of the tunnel
        user_token: String,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<&'crypto F>,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        /// If the udp socket need respond to client
        need_response: bool,
        /// The udp data of the udp packet
        udp_data: Bytes,
    },
}
impl<'crypto, F> TunnelState for AgentAcceptedState<'crypto, F> where F: RsaCryptoFetcher + Clone {}
impl<F> Display for AgentAcceptedState<'_, F>
where
    F: RsaCryptoFetcher + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "AGENT_ACCEPTED")
    }
}
/// The destination connected state of the tunnel
pub(crate) enum DestConnectedState<'crypto, F>
where
    F: RsaCryptoFetcher + Clone,
{
    Tcp {
        /// The user token of the tunnel
        user_token: String,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead<&'crypto F>,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<&'crypto F>,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        dst_connection: Framed<TimeoutStream<TcpStream>, BytesCodec>,
    },
    Udp {
        /// The user token of the tunnel
        user_token: String,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<&'crypto F>,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        /// If the udp socket need respond to client
        need_response: bool,
        /// The destination udp socket
        dst_udp_socket: UdpSocket,
        /// The udp data of the udp packet
        udp_data: Bytes,
    },
}
impl<'crypto, F> TunnelState for DestConnectedState<'crypto, F> where F: RsaCryptoFetcher + Clone {}
impl<F> Display for DestConnectedState<'_, F>
where
    F: RsaCryptoFetcher + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "DESTINATION_CONNECTED")
    }
}
/// The relay state of the tunnel
pub(crate) struct RelayState;
impl TunnelState for RelayState {}
impl Display for RelayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        write!(f, "RELAY")
    }
}
