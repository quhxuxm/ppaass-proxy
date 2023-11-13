use std::{
    collections::HashMap,
    fs::{read_dir, File},
    path::Path,
    sync::{Arc, Once},
};

use log::error;
use ppaass_crypto::{CryptoError, RsaCrypto, RsaCryptoFetcher};

use crate::config::SERVER_CONFIG;

#[derive(Debug)]
pub(crate) struct ProxyRsaCryptoFetcher {
    cache: HashMap<String, RsaCrypto>,
}

impl ProxyRsaCryptoFetcher {
    pub fn new() -> Result<Self, CryptoError> {
        let mut result = Self {
            cache: HashMap::new(),
        };
        let rsa_dir_path = SERVER_CONFIG.get_rsa_dir();
        let rsa_dir = read_dir(&rsa_dir_path).map_err(|e| {
            CryptoError::Rsa(format!(
                "Fail to load rsa crypto from directory [{rsa_dir_path:?}] because of error: {e:?}"
            ))
        })?;
        rsa_dir.for_each(|entry| {
            let Ok(entry) = entry else {
                error!("fail to read {rsa_dir_path:?} directory");
                return;
            };
            let user_token = entry.file_name();
            let user_token = user_token.to_str();
            let Some(user_token) = user_token else {
                error!(
                    "fail to read {rsa_dir_path:?}{:?} directory because of user token not exist",
                    entry.file_name()
                );
                return;
            };

            let public_key_path = rsa_dir_path.join(user_token).join("AgentPublicKey.pem");
            let public_key_path = Path::new(&public_key_path);
            let Ok(public_key_file) = File::open(public_key_path) else {
                error!("Fail to read public key file: {public_key_path:?}.");
                return;
            };
            let private_key_path = rsa_dir_path.join(user_token).join("ProxyPrivateKey.pem");
            let private_key_path = Path::new(Path::new(&private_key_path));
            let Ok(private_key_file) = File::open(private_key_path) else {
                error!("Fail to read private key file :{private_key_path:?}.");
                return;
            };

            let Ok(rsa_crypto) = RsaCrypto::new(public_key_file, private_key_file) else {
                error!("Fail to create rsa crypto for user: {user_token}.");
                return;
            };
            result.cache.insert(user_token.to_string(), rsa_crypto);
        });
        Ok(result)
    }
}

impl RsaCryptoFetcher for ProxyRsaCryptoFetcher {
    fn fetch(&self, user_token: &str) -> Result<Option<&RsaCrypto>, CryptoError> {
        Ok(self.cache.get(user_token))
    }
}
