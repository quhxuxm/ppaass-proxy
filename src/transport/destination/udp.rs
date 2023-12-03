use crate::error::ProxyError;
use crate::server::AgentInboundMessage;

pub(crate) struct DestUdpHandler {}

impl DestUdpHandler {
    pub fn new() -> Self {
        todo!()
    }

    pub async fn handle_message(&self, input: AgentInboundMessage) -> Result<(), ProxyError> {
        todo!()
    }
}
