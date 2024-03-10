use crate::crypto::ProxyServerRsaCryptoFetcher;
use crate::error::ProxyServerError;
use bytes::BytesMut;
use ppaass_codec::codec::agent::PpaassAgentMessageDecoder;
use ppaass_codec::codec::proxy::PpaassProxyMessageEncoder;

use ppaass_protocol::message::{PpaassAgentMessage, PpaassProxyMessage};
use tokio_util::codec::{Decoder, Encoder};

pub(crate) struct PpaassAgentEdgeCodec {
    encoder: PpaassProxyMessageEncoder<ProxyServerRsaCryptoFetcher>,
    decoder: PpaassAgentMessageDecoder<ProxyServerRsaCryptoFetcher>,
}

impl PpaassAgentEdgeCodec {
    pub fn new(compress: bool, rsa_crypto_fetcher: ProxyServerRsaCryptoFetcher) -> Self {
        Self {
            encoder: PpaassProxyMessageEncoder::new(compress, rsa_crypto_fetcher.clone()),
            decoder: PpaassAgentMessageDecoder::new(rsa_crypto_fetcher),
        }
    }
}

impl Encoder<PpaassProxyMessage> for PpaassAgentEdgeCodec {
    type Error = ProxyServerError;

    fn encode(&mut self, item: PpaassProxyMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encoder
            .encode(item, dst)
            .map_err(ProxyServerError::Codec)
    }
}

impl Decoder for PpaassAgentEdgeCodec {
    type Item = PpaassAgentMessage;
    type Error = ProxyServerError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decoder.decode(src).map_err(ProxyServerError::Codec)
    }
}
