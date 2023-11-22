use std::sync::Arc;

use futures_util::stream::{SplitSink, SplitStream};
use ppaass_io::Connection;
use ppaass_protocol::message::WrapperMessage;

use crate::crypto::ProxyRsaCryptoFetcher;

pub(crate) type AgentConnectionWrite<T> =
    SplitSink<Connection<T, Arc<ProxyRsaCryptoFetcher>>, WrapperMessage>;

pub(crate) type AgentConnectionRead<T> = SplitStream<Connection<T, Arc<ProxyRsaCryptoFetcher>>>;

pub(crate) struct AgentInputMessage {
    pub agent_connection_id: String,
    pub wrapper_message: WrapperMessage,
}
