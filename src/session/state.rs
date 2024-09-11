use super::{AgentConnectionRead, AgentConnectionWrite};
use bytes::Bytes;
use derive_more::Display;
use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_protocol::message::values::{
    address::PpaassUnifiedAddress, encryption::PpaassMessagePayloadEncryption,
};
use tokio::net::UdpSocket;
use tokio_io_timeout::TimeoutStream;
use tokio_tfo::TfoStream;
use tokio_util::codec::{BytesCodec, Framed};
pub enum AgentAcceptedData<F>
where
    F: RsaCryptoFetcher + Clone + Sync + Send + 'static,
{
    Tcp {
        /// The user token of the session
        user_token: String,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead<F>,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<F>,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
    },
    Udp {
        /// The user token of the session
        user_token: String,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<F>,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead<F>,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The destination address
        dst_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        /// The udp data of the udp packet
        udp_data: Bytes,
    },
}
pub enum DestConnectedData<F>
where
    F: RsaCryptoFetcher + Clone + Sync + Send + 'static,
{
    Tcp {
        /// The user token of the session
        user_token: String,
        /// The agent connection read part
        agent_connection_read: AgentConnectionRead<F>,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<F>,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        /// The source address from the client
        dst_address: PpaassUnifiedAddress,
        dst_connection: Framed<TimeoutStream<TfoStream>, BytesCodec>,
    },
    Udp {
        /// The user token of the session
        user_token: String,
        /// The agent connection write part
        agent_connection_write: AgentConnectionWrite<F>,
        /// The agent connection read part
        _agent_connection_read: AgentConnectionRead<F>,
        /// The source address from the client
        src_address: PpaassUnifiedAddress,
        /// The payload encryption
        payload_encryption: PpaassMessagePayloadEncryption,
        /// The source address from the client
        dst_address: PpaassUnifiedAddress,
        dst_udp: UdpSocket,
        udp_data: Bytes,
    },
}
/// The session state.

#[derive(Display, Default)]
pub enum SessionState<F>
where
    F: RsaCryptoFetcher + Clone + Sync + Send + 'static,
{
    #[display("INIT")]
    Init,
    #[display("AGENT-ACCEPTED")]
    AgentAccepted(AgentAcceptedData<F>),
    #[display("DEST-CONNECTED")]
    DestConnected(DestConnectedData<F>),
    #[display("RELAY")]
    Relay,
    #[display("INVALID")]
    #[default]
    Invalid,
}
