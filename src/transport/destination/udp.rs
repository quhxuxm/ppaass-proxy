use bytes::Bytes;

use crate::error::ProxyError;

use super::HandlerInput;

pub(crate) struct DestUdpHandler {}

impl DestUdpHandler {
    pub fn new() -> Self {
        todo!()
    }

    pub async fn handle_message(&self, input: HandlerInput) -> Result<(), ProxyError> {
        todo!()
    }
}
