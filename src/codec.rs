use bytes::BytesMut;
use ppaass_codec::codec::agent::PpaassAgentMessageDecoder;
use ppaass_codec::codec::proxy::PpaassProxyMessageEncoder;
use ppaass_crypto::crypto::RsaCryptoFetcher;
use ppaass_protocol::message::{PpaassAgentMessage, PpaassProxyMessage};
use tokio_util::codec::{Decoder, Encoder};
use crate::error::ProxyServerError;
pub struct PpaassAgentEdgeCodec<F>
    where
        F: RsaCryptoFetcher + Clone,
{
    encoder: PpaassProxyMessageEncoder<F>,
    decoder: PpaassAgentMessageDecoder<F>,
}
impl<F> PpaassAgentEdgeCodec<F>
    where
        F: RsaCryptoFetcher + Clone,
{
    pub fn new(compress: bool, rsa_crypto_fetcher: F) -> Self {
        Self {
            encoder: PpaassProxyMessageEncoder::new(compress, rsa_crypto_fetcher.clone()),
            decoder: PpaassAgentMessageDecoder::new(rsa_crypto_fetcher),
        }
    }
}
impl<F> Encoder<PpaassProxyMessage> for PpaassAgentEdgeCodec<F>
    where
        F: RsaCryptoFetcher + Clone,
{
    type Error = ProxyServerError;
    fn encode(&mut self, item: PpaassProxyMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encoder
            .encode(item, dst)
            .map_err(ProxyServerError::Codec)
    }
}
impl<F> Decoder for PpaassAgentEdgeCodec<F>
    where
        F: RsaCryptoFetcher + Clone,
{
    type Item = PpaassAgentMessage;
    type Error = ProxyServerError;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decoder.decode(src).map_err(ProxyServerError::Codec)
    }
}
