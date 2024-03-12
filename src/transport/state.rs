use std::fmt::Display;

use bytes::Bytes;

use ppaass_protocol::message::values::{
    address::PpaassUnifiedAddress, encryption::PpaassMessagePayloadEncryption,
};
use tokio::net::{TcpStream, UdpSocket};
use tokio_io_timeout::TimeoutStream;
use tokio_util::codec::{BytesCodec, Framed};

use super::{AgentConnectionRead, AgentConnectionWrite};

/// The marker trait for transport state.
pub(crate) trait TransportState {}

/// The initial state of the transport
pub(crate) struct InitState;

impl TransportState for InitState {}

impl Display for InitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "INIT")
    }
}

/// The agent accepted state of the transport
pub(crate) enum AgentAcceptedState {
    Tcp {
        /// The user token of the transport
        user_token: String,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
    },
    Udp {
        /// The user token of the transport
        user_token: String,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        /// If the udp socket need response to client
        need_response: bool,
        /// The udp data of the udp packet
        udp_data: Bytes,
    },
}

impl TransportState for AgentAcceptedState {}

impl Display for AgentAcceptedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AGENT_ACCEPTED")
    }
}

/// The destinition connected state of the transport
pub(crate) enum DestConnectedState {
    Tcp {
        /// The user token of the transport
        user_token: String,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        dst_connection: Framed<TimeoutStream<TcpStream>, BytesCodec>,
    },
    Udp {
        /// The user token of the transport
        user_token: String,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        /// If the udp socket need response to client
        need_response: bool,
        /// The destination udp socket
        dst_udp_socket: UdpSocket,
        /// The udp data of the udp packet
        udp_data: Bytes,
    },
}

impl TransportState for DestConnectedState {}

impl Display for DestConnectedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DESTINITION_CONNECTED")
    }
}

/// The relay state of the transport
pub(crate) struct RelayState;

impl TransportState for RelayState {}

impl Display for RelayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RELAY")
    }
}
