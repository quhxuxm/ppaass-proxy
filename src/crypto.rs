use crate::config::{CryptoStorage, ProxyConfig};
use ppaass_crypto::crypto::{RsaCrypto, RsaCryptoFetcher};
use ppaass_crypto::error::CryptoError;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use std::sync::Arc;
use std::{
    collections::HashMap,
    fs::{read_dir, File},
    path::Path,
};
use tracing::error;
#[derive(Debug, Clone)]
pub struct StaticFileRsaCryptoFetcher {
    cache: Arc<HashMap<String, RsaCrypto>>,
}
impl StaticFileRsaCryptoFetcher {
    pub fn new(config: &ProxyConfig) -> Result<Self, CryptoError> {
        let mut cache = HashMap::new();
        match config.crypto_storage() {
            CryptoStorage::File => {
                let rsa_dir_path = config.rsa_dir();
                let rsa_dir = read_dir(rsa_dir_path)?;
                rsa_dir.for_each(|entry| {
                    let Ok(entry) = entry else {
                        error!("fail to read {rsa_dir_path:?} directory");
                        return;
                    };
                    let user_token = entry.file_name();
                    let user_token = user_token.to_str();
                    let Some(user_token) = user_token else {
                        error!("Fail to read {rsa_dir_path:?}{:?} directory because of user token not exist", entry.file_name());
                        return;
                    };
                    let public_key_path = rsa_dir_path.join(user_token).join("AgentPublicKey.pem");
                    let Ok(public_key_file) = File::open(&public_key_path) else {
                        error!("Fail to read public key file: {public_key_path:?}.");
                        return;
                    };
                    let private_key_path =
                        rsa_dir_path.join(user_token).join("ProxyPrivateKey.pem");
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
            CryptoStorage::Database => Ok(Self {
                cache: Arc::new(cache),
            }),
        }
    }
}
impl RsaCryptoFetcher for StaticFileRsaCryptoFetcher {
    fn fetch(&self, user_token: impl AsRef<str>) -> Result<Option<&RsaCrypto>, CryptoError> {
        Ok(self.cache.get(user_token.as_ref()))
    }
}
pub struct ProxyServerPayloadEncryptionSelector {}
impl PpaassMessagePayloadEncryptionSelector for ProxyServerPayloadEncryptionSelector {}
