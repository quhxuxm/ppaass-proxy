mod config;
mod crypto;
mod error;
mod server;
mod transport;
mod types;

use std::sync::{Arc, OnceLock};

use config::SERVER_CONFIG;
use crypto::ProxyRsaCryptoFetcher;

use crate::server::Server;
use anyhow::Result;
use log::{error, info};
use tokio::runtime::Builder;

const LOG_CONFIG_FILE_PATH: &str = "resources/config/ppaass-proxy-log.yml";
const SERVER_RUNTIME_NAME: &str = "PROXY-SERVER";

pub(crate) static RSA_CRYPTO_FETCHER: OnceLock<Arc<ProxyRsaCryptoFetcher>> = OnceLock::new();

fn main() -> Result<()> {
    log4rs::init_file(LOG_CONFIG_FILE_PATH, Default::default())?;
    RSA_CRYPTO_FETCHER
        .set(Arc::new(ProxyRsaCryptoFetcher::new()?))
        .expect("Fail to set rsa crypto fetcher.");
    let server_runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name(SERVER_RUNTIME_NAME)
        .worker_threads(SERVER_CONFIG.get_worker_thread_number())
        .build()?;

    server_runtime.block_on(async {
        info!("Begin to start proxy server.");
        if let Err(e) = Server::start().await {
            error!("Fail to start proxy server because of error: {e:?}");
            return;
        }
        info!("Success to stop proxy server.");
    });
    Ok(())
}
