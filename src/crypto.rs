use std::sync::Arc;
use std::{
    collections::HashMap,
    fs::{read_dir, File},
    path::Path,
};

use lazy_static::lazy_static;
use ppaass_crypto::crypto::{RsaCrypto, RsaCryptoFetcher};
use ppaass_crypto::error::CryptoError;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use tracing::error;

use crate::config::PROXY_CONFIG;

lazy_static! {
    pub(crate) static ref RSA_CRYPTO: ProxyServerRsaCryptoFetcher =
        ProxyServerRsaCryptoFetcher::new().expect("Can not initialize proxy rsa crypto fetcher.");
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyServerRsaCryptoFetcher {
    cache: Arc<HashMap<String, RsaCrypto>>,
}

impl ProxyServerRsaCryptoFetcher {
    pub(crate) fn new() -> Result<Self, CryptoError> {
        let mut cache = HashMap::new();
        let rsa_dir_path = PROXY_CONFIG.get_rsa_dir();
        let rsa_dir = read_dir(rsa_dir_path)?;
        rsa_dir.for_each(|entry| {
            let Ok(entry) = entry else {
                error!("fail to read {rsa_dir_path} directory");
                return;
            };
            let user_token = entry.file_name();
            let user_token = user_token.to_str();
            let Some(user_token) = user_token else {
                error!(
                    "fail to read {}{:?} directory because of user token not exist",
                    rsa_dir_path,
                    entry.file_name()
                );
                return;
            };
            let public_key_path = format!("{rsa_dir_path}{user_token}/AgentPublicKey.pem");
            let public_key_path = Path::new(&public_key_path);
            let Ok(public_key_file) = File::open(public_key_path) else {
                error!("Fail to read public key file: {public_key_path:?}.");
                return;
            };
            let private_key_path = format!("{rsa_dir_path}{user_token}/ProxyPrivateKey.pem");
            let private_key_path = Path::new(Path::new(&private_key_path));
            let Ok(private_key_file) = File::open(private_key_path) else {
                error!("Fail to read private key file :{private_key_path:?}.");
                return;
            };

            let Ok(rsa_crypto) = RsaCrypto::new(public_key_file, private_key_file) else {
                error!("Fail to create rsa crypto for user: {user_token}.");
                return;
            };
            cache.insert(user_token.to_string(), rsa_crypto);
        });
        Ok(Self {
            cache: Arc::new(cache),
        })
    }
}

impl RsaCryptoFetcher for ProxyServerRsaCryptoFetcher {
    fn fetch(&self, user_token: impl AsRef<str>) -> Result<Option<&RsaCrypto>, CryptoError> {
        Ok(self.cache.get(user_token.as_ref()))
    }
}

pub(crate) struct ProxyServerPayloadEncryptionSelector {}

impl PpaassMessagePayloadEncryptionSelector for ProxyServerPayloadEncryptionSelector {}
