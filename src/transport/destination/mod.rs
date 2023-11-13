mod tcp;
mod udp;

use bytes::Bytes;
pub(crate) use tcp::*;
pub(crate) use udp::*;

pub(crate) struct HandlerInput {
    pub unique_id: String,
    pub user_token: String,
    pub payload: Bytes,
}
