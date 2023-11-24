use std::sync::Arc;

use futures_util::stream::{SplitSink, SplitStream};
use ppaass_io::Connection;
use ppaass_protocol::message::{AgentTcpPayload, AgentUdpPayload, WrapperMessage};

use crate::crypto::ProxyRsaCryptoFetcher;

pub(crate) type AgentConnectionWrite<T> =
    SplitSink<Connection<T, Arc<ProxyRsaCryptoFetcher>>, WrapperMessage>;

pub(crate) type AgentConnectionRead<T> = SplitStream<Connection<T, Arc<ProxyRsaCryptoFetcher>>>;

pub(crate) struct AgentInputTcpMessage {
    pub unique_id: String,
    /// The user token
    pub user_token: String,
    /// The agent tcp connection id
    pub agent_connection_id: String,
    /// The payload of the agent input message
    pub payload: AgentTcpPayload,
}

pub(crate) struct AgentInputUdpMessage {
    pub unique_id: String,
    /// The user token
    pub user_token: String,
    /// The raw agent tcp connection id
    pub agent_connection_id: String,
    /// The payload of the agent input message
    pub payload: AgentUdpPayload,
}
