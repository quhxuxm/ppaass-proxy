use ppaass_protocol::message::WrapperMessage;

use crate::error::ProxyError;

pub(crate) struct DestUdpHandler {}

impl DestUdpHandler {
    pub fn new() -> Self {
        todo!()
    }

    pub async fn handle_message(&self, input: WrapperMessage) -> Result<(), ProxyError> {
        todo!()
    }
}
